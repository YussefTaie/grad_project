"""
context_layer.py  —  Context Awareness Layer
=============================================
Wraps the BaselineEngine and adds higher-level *context signals*
that help detectors distinguish:
  • Legitimate high-throughput traffic  (browsing, downloads, streaming)
  • Malicious repetitive / concentrated patterns  (DDoS, BruteForce)

Public API
----------
    from context_layer import ContextLayer, TrafficVerdict
    ctx_layer = ContextLayer()               # shares the global BaselineEngine

    # Call once per completed flow:
    ctx_layer.observe(flow_dict)

    # Before raising an alert:
    verdict = ctx_layer.evaluate(flow_dict, raw_pps=pps)
    if verdict.is_suspicious:
        ...

Verdicts
--------
    TrafficVerdict.NORMAL        — unlikely to be an attack
    TrafficVerdict.BORDERLINE    — elevated but ambiguous
    TrafficVerdict.SUSPICIOUS    — strong contextual signals
    TrafficVerdict.ATTACK        — multiple independent signals

Internal signals checked
------------------------
  1. Adaptive PPS threshold (baseline-aware)
  2. Target diversity       (high diversity → likely benign)
  3. Repetition concentration (same dst → suspicious)
  4. Protocol symmetry      (fwd/bwd ratio)
  5. Burst vs sustained     (short spike vs long elevation)
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from collections import defaultdict, deque

from baseline_engine import BaselineEngine, get_engine, FlowContext, BASELINE_K


# ── Verdict enum ──────────────────────────────────────────────────────────────
class TrafficVerdict(str, Enum):
    NORMAL     = "NORMAL"
    BORDERLINE = "BORDERLINE"
    SUSPICIOUS = "SUSPICIOUS"
    ATTACK     = "ATTACK"


# ── Result object ─────────────────────────────────────────────────────────────
@dataclass
class ContextResult:
    verdict         : TrafficVerdict = TrafficVerdict.NORMAL
    reasons         : list[str]      = field(default_factory=list)
    is_high_diversity: bool          = False
    is_repetitive   : bool           = False
    pps             : float          = 0.0
    adaptive_thr    : float          = 0.0
    signal_count    : int            = 0        # how many alarm signals fired

    @property
    def is_suspicious(self) -> bool:
        return self.verdict in (TrafficVerdict.SUSPICIOUS, TrafficVerdict.ATTACK)

    @property
    def is_attack(self) -> bool:
        return self.verdict == TrafficVerdict.ATTACK


# ── Helpers ───────────────────────────────────────────────────────────────────
def _get(d: dict, *keys, default=None):
    for k in keys:
        v = d.get(k)
        if v is not None and v != "":
            return v
    return default


def _float(d: dict, *keys, default=0.0) -> float:
    v = _get(d, *keys)
    try:
        return float(v) if v is not None else default
    except (ValueError, TypeError):
        return default


# ── Burst tracker (per-IP recent PPS history) ─────────────────────────────────
_BURST_WINDOW = 30   # seconds to track for burst detection


class _BurstTracker:
    """Tracks PPS values in a rolling 30-second window to detect bursts."""

    def __init__(self):
        # { src_ip → deque[(timestamp, pps)] }
        self._windows: dict = defaultdict(lambda: deque())

    def record(self, src_ip: str, pps: float, now: float):
        dq = self._windows[src_ip]
        dq.append((now, pps))
        cutoff = now - _BURST_WINDOW
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def is_sustained(self, src_ip: str, threshold: float) -> bool:
        """Return True if PPS has been above threshold for > half the window."""
        dq = self._windows.get(src_ip)
        if not dq or len(dq) < 3:
            return False
        above = sum(1 for _, pps in dq if pps > threshold)
        return (above / len(dq)) >= 0.5


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════
class ContextLayer:
    """
    Context Awareness Layer — wraps BaselineEngine and adds rich signal checks.

    Usage (in unified_agent.py or any detector):
        _ctx = ContextLayer()          # create once, share across threads

        # Feed every completed flow:
        _ctx.observe(flow)

        # Evaluate context before escalating an alert:
        result = _ctx.evaluate(flow, raw_pps=features["Packets per Second"])
        if result.is_high_diversity and not result.is_repetitive:
            # Many different targets, not concentrated → likely benign
            suppress_alert()
    """

    def __init__(self, engine: Optional[BaselineEngine] = None):
        self._engine  = engine or get_engine()
        self._bursts  = _BurstTracker()

    # ------------------------------------------------------------------
    # Feed
    # ------------------------------------------------------------------
    def observe(self, flow: dict):
        """Update the baseline engine with a completed flow."""
        self._engine.update(flow)

        src_ip = (
            _get(flow, "Src IP", "Source IP", "src_ip") or "unknown"
        )
        pps = _float(flow, "Packets per Second")
        now = time.time()
        self._bursts.record(src_ip, pps, now)

    # ------------------------------------------------------------------
    # Evaluate
    # ------------------------------------------------------------------
    def evaluate(self, flow: dict, raw_pps: float = 0.0) -> ContextResult:
        """
        Return a ContextResult for *flow*.

        Parameters
        ----------
        flow    : the flow feature dict
        raw_pps : pre-computed PPS value (if already available)
        """
        src_ip = (
            _get(flow, "Src IP", "Source IP", "src_ip") or "unknown"
        )
        if raw_pps == 0.0:
            raw_pps = _float(flow, "Packets per Second")

        ctx: FlowContext = self._engine.get_context(src_ip)
        adaptive_thr     = self._engine.adaptive_ddos_threshold(src_ip)

        reasons      : list[str] = []
        signal_count : int       = 0

        # ── Signal 1: Adaptive PPS ─────────────────────────────────────────
        pps_flagged = raw_pps > adaptive_thr
        if pps_flagged:
            reasons.append(
                f"PPS={raw_pps:.1f} > adaptive_thr={adaptive_thr:.1f}"
            )
            signal_count += 1

        # ── Signal 2: Repetition concentration ────────────────────────────
        if ctx.is_repetitive:
            reasons.append(
                f"repetitive: {ctx.same_target_ratio*100:.0f}% to same dst"
            )
            signal_count += 1

        # ── Signal 3: Target diversity (mitigating factor) ─────────────────
        high_diversity = ctx.is_high_diversity
        if high_diversity and pps_flagged:
            # Many different targets: discredit the PPS alarm
            reasons.append(
                f"HIGH DIVERSITY ({ctx.unique_dst_count} unique dsts) "
                f"→ PPS alarm down-weighted"
            )
            signal_count = max(0, signal_count - 1)

        # ── Signal 4: Burst vs sustained ──────────────────────────────────
        sustained = self._bursts.is_sustained(src_ip, adaptive_thr)
        if pps_flagged and sustained:
            reasons.append("sustained elevated PPS (>50% of last 30s)")
            signal_count += 1
        elif pps_flagged and not sustained:
            reasons.append("transient PPS spike (likely benign burst)")
            signal_count = max(0, signal_count - 1)

        # ── Signal 5: Fwd/Bwd asymmetry ───────────────────────────────────
        fwd = _float(flow, "Total Fwd Packets")
        bwd = _float(flow, "Total Backward Packets") or 1.0
        if fwd / bwd > 20 and fwd > 50:
            reasons.append(f"high fwd/bwd asymmetry ({fwd/bwd:.1f}x)")
            signal_count += 1

        # ── Verdict ───────────────────────────────────────────────────────
        if signal_count == 0:
            verdict = TrafficVerdict.NORMAL
        elif signal_count == 1:
            verdict = TrafficVerdict.BORDERLINE
        elif signal_count == 2:
            verdict = TrafficVerdict.SUSPICIOUS
        else:
            verdict = TrafficVerdict.ATTACK

        return ContextResult(
            verdict          = verdict,
            reasons          = reasons,
            is_high_diversity= high_diversity,
            is_repetitive    = ctx.is_repetitive,
            pps              = raw_pps,
            adaptive_thr     = adaptive_thr,
            signal_count     = signal_count,
        )

    # ------------------------------------------------------------------
    # Convenience check used by the upgraded DDoS detector
    # ------------------------------------------------------------------
    def should_flag_ddos(
        self, src_ip: str, pps: float, raw_alerts: int
    ) -> tuple[bool, str]:
        """
        Returns (should_flag: bool, reason: str).

        Logic:
          - pps must exceed the *adaptive* threshold (not a fixed value)
          - raw_alerts (windows above threshold) still applies
          - BUT if the traffic is highly diverse → suppress
          - AND if the traffic is NOT sustained  → suppress (transient burst)
        """
        adaptive_thr = self._engine.adaptive_ddos_threshold(src_ip)
        ctx          = self._engine.get_context(src_ip)

        if pps <= adaptive_thr:
            return False, f"PPS {pps:.1f} ≤ adaptive_thr {adaptive_thr:.1f}"

        if ctx.is_high_diversity and not ctx.is_repetitive:
            return False, (
                f"high diversity ({ctx.unique_dst_count} dsts) "
                f"with low repetition → likely benign"
            )

        if raw_alerts < 2:
            return False, f"only {raw_alerts} alert windows (need ≥ 2)"

        sustained = self._bursts.is_sustained(src_ip, adaptive_thr)
        if not sustained and raw_alerts < 4:
            return False, "transient PPS spike, not sustained"

        reason = (
            f"PPS {pps:.1f} > adaptive_thr {adaptive_thr:.1f}, "
            f"alerts={raw_alerts}, "
            f"repetitive={ctx.is_repetitive}"
        )
        return True, reason


# ── Module-level singleton ────────────────────────────────────────────────────
_default_ctx: Optional[ContextLayer] = None


def get_context_layer() -> ContextLayer:
    """Process-wide singleton ContextLayer."""
    global _default_ctx
    if _default_ctx is None:
        _default_ctx = ContextLayer()
    return _default_ctx
