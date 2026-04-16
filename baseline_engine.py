"""
baseline_engine.py  —  Adaptive Baseline Learning Engine
=========================================================
Learns *normal* traffic behaviour dynamically and exposes
adaptive thresholds so that detectors are tuned to the
current environment rather than fixed magic numbers.

Key concepts
------------
* Per-IP rolling statistics  (packets per second, connections
  per window, average flow size)
* Global rolling statistics   (same metrics, aggregated)
* Adaptive threshold          = mean + k * std  (k configurable)
* Context signals             (target diversity, protocol mix,
  repetition ratio)  used by the Context Awareness Layer

Thread-safe: all public methods use a single RLock.

Public API
----------
    from baseline_engine import BaselineEngine
    engine = BaselineEngine()

    # Call once per completed flow:
    engine.update(flow_dict)

    # Query adaptive DDoS threshold for a specific IP:
    threshold = engine.adaptive_ddos_threshold(src_ip)

    # Query context object for a specific IP:
    ctx = engine.get_context(src_ip)
    print(ctx.is_high_diversity)   # True → many different targets
    print(ctx.is_repetitive)       # True → same target over and over
"""

import time
import math
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

# ── Configurable parameters ────────────────────────────────────────────────────
BASELINE_K              = 2.5   # σ multiplier for adaptive threshold
BASELINE_WINDOW_SEC     = 300   # 5-minute rolling window for per-IP stats
GLOBAL_WINDOW_SEC       = 300   # same for global stats
DIVERSITY_THRESHOLD     = 10    # unique dst IPs in window → "high diversity"
REPETITION_THRESHOLD    = 0.75  # fraction going to same target → "repetitive"
MIN_SAMPLES_ADAPTIVE    = 10    # need at least N samples before adapting
ABSOLUTE_MAX_PPS        = 10_000  # hard ceiling – never allow above this


# ── Helper: online Welford mean/variance ───────────────────────────────────────
class _OnlineStat:
    """Welford online algorithm for mean & variance – no list storage needed."""

    __slots__ = ("n", "_mean", "_M2")

    def __init__(self):
        self.n    = 0
        self._mean = 0.0
        self._M2   = 0.0

    def update(self, x: float):
        self.n += 1
        delta   = x - self._mean
        self._mean += delta / self.n
        self._M2   += delta * (x - self._mean)

    @property
    def mean(self) -> float:
        return self._mean

    @property
    def std(self) -> float:
        if self.n < 2:
            return 0.0
        return math.sqrt(self._M2 / self.n)

    def adaptive_threshold(self, k: float = BASELINE_K) -> float:
        """mean + k*std, clamped to ABSOLUTE_MAX_PPS."""
        return min(self._mean + k * self.std, ABSOLUTE_MAX_PPS)


# ── Context object returned to callers ────────────────────────────────────────
@dataclass
class FlowContext:
    """Snapshot of contextual signals for one src_ip."""
    src_ip          : str
    unique_dst_count: int   = 0     # distinct dst IPs in window
    total_flows     : int   = 0     # total flows in window
    same_target_ratio: float = 0.0  # fraction of flows to most-seen dst
    avg_pps         : float = 0.0
    std_pps         : float = 0.0
    adaptive_pps_thr: float = 0.0

    @property
    def is_high_diversity(self) -> bool:
        """Many different targets → likely normal browsing / scan."""
        return self.unique_dst_count >= DIVERSITY_THRESHOLD

    @property
    def is_repetitive(self) -> bool:
        """Most traffic aimed at ONE target → suspicious concentration."""
        return (
            self.total_flows >= 5
            and self.same_target_ratio >= REPETITION_THRESHOLD
        )

    @property
    def is_baseline_ready(self) -> bool:
        return self.total_flows >= MIN_SAMPLES_ADAPTIVE


# ── Per-IP state ───────────────────────────────────────────────────────────────
class _IPState:
    """Mutable state tracked per source IP."""

    def __init__(self):
        self.pps_stat       = _OnlineStat()
        self.conn_stat      = _OnlineStat()   # connections per BASELINE_WINDOW_SEC
        self.fsize_stat     = _OnlineStat()   # average flow size (bytes)
        # Rolling window for diversity & repetition
        self._window: deque = deque()          # (timestamp, dst_ip)

    def record(self, pps: float, flow_bytes: float, dst_ip: str, now: float):
        self.pps_stat.update(pps)
        self.fsize_stat.update(flow_bytes)

        self._window.append((now, dst_ip))
        # Purge old entries
        cutoff = now - BASELINE_WINDOW_SEC
        while self._window and self._window[0][0] < cutoff:
            self._window.popleft()

    def context(self, src_ip: str) -> FlowContext:
        entries     = list(self._window)
        total       = len(entries)
        unique_dsts = len({dst for _, dst in entries})

        # Most common dst
        if total > 0:
            from collections import Counter
            top_count  = Counter(dst for _, dst in entries).most_common(1)[0][1]
            same_ratio = top_count / total
        else:
            same_ratio = 0.0

        return FlowContext(
            src_ip           = src_ip,
            unique_dst_count = unique_dsts,
            total_flows      = total,
            same_target_ratio= same_ratio,
            avg_pps          = self.pps_stat.mean,
            std_pps          = self.pps_stat.std,
            adaptive_pps_thr = self.pps_stat.adaptive_threshold(),
        )


# ── Global rolling stat (all IPs combined) ────────────────────────────────────
class _GlobalState:
    def __init__(self):
        self.pps_stat   = _OnlineStat()
        self.fsize_stat = _OnlineStat()

    def record(self, pps: float, flow_bytes: float):
        self.pps_stat.update(pps)
        self.fsize_stat.update(flow_bytes)

    def adaptive_pps_threshold(self) -> float:
        return self.pps_stat.adaptive_threshold()


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════
class BaselineEngine:
    """
    Singleton-friendly baseline engine.  Create ONE instance per process
    and share it across threads.

    Usage
    -----
        engine = BaselineEngine()

        # In your flow-processing loop:
        engine.update(flow_dict)

        # Before calling the DDoS detector:
        thr = engine.adaptive_ddos_threshold(src_ip, fallback=150)
        if pps > thr:
            ...  # elevated suspicion
    """

    def __init__(self, k: float = BASELINE_K):
        self._k      = k
        self._lock   = threading.RLock()
        self._ips: dict[str, _IPState] = defaultdict(_IPState)
        self._global = _GlobalState()

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------
    def update(self, flow: dict):
        """
        Ingest a completed flow record.
        Supports both unified_agent format and CSV column names.
        """
        src_ip = (
            flow.get("Src IP") or flow.get("Source IP") or
            flow.get("src_ip", "unknown")
        )
        dst_ip = (
            flow.get("Dst IP") or flow.get("Destination IP") or
            flow.get("dst_ip", "unknown")
        )

        try:
            pps = float(flow.get("Packets per Second", 0) or 0)
        except (ValueError, TypeError):
            pps = 0.0

        try:
            flow_bytes = float(
                flow.get("Total Bytes") or
                flow.get("Total Length of Fwd Packets") or 0
            )
        except (ValueError, TypeError):
            flow_bytes = 0.0

        now = time.time()
        with self._lock:
            self._ips[src_ip].record(pps, flow_bytes, dst_ip, now)
            self._global.record(pps, flow_bytes)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def adaptive_ddos_threshold(
        self, src_ip: str, fallback: float = 150.0
    ) -> float:
        """
        Returns the adaptive PPS threshold for *src_ip*.

        * If we have enough samples for that IP  → per-IP adaptive threshold.
        * If global baseline is ready            → global adaptive threshold.
        * Otherwise                              → fallback (original fixed value).
        """
        with self._lock:
            ip_state = self._ips.get(src_ip)
            if ip_state and ip_state.pps_stat.n >= MIN_SAMPLES_ADAPTIVE:
                return ip_state.pps_stat.adaptive_threshold(self._k)

            if self._global.pps_stat.n >= MIN_SAMPLES_ADAPTIVE:
                return self._global.adaptive_pps_threshold()

        return fallback

    def get_context(self, src_ip: str) -> FlowContext:
        """Return a FlowContext snapshot for *src_ip*."""
        with self._lock:
            state = self._ips.get(src_ip)
            if state:
                return state.context(src_ip)
        # Never seen this IP
        return FlowContext(src_ip=src_ip)

    def global_adaptive_threshold(self, fallback: float = 150.0) -> float:
        """Global (all-IP) adaptive PPS threshold."""
        with self._lock:
            if self._global.pps_stat.n >= MIN_SAMPLES_ADAPTIVE:
                return self._global.adaptive_pps_threshold()
        return fallback

    def stats_summary(self) -> dict:
        """Diagnostic snapshot (for logging / API endpoint)."""
        with self._lock:
            return {
                "tracked_ips"     : len(self._ips),
                "global_pps_mean" : round(self._global.pps_stat.mean, 3),
                "global_pps_std"  : round(self._global.pps_stat.std,  3),
                "global_pps_thr"  : round(self._global.adaptive_pps_threshold(), 3),
                "global_n"        : self._global.pps_stat.n,
            }


# ── Module-level singleton (import and reuse) ─────────────────────────────────
_default_engine: Optional[BaselineEngine] = None


def get_engine() -> BaselineEngine:
    """Return the process-wide singleton BaselineEngine."""
    global _default_engine
    if _default_engine is None:
        _default_engine = BaselineEngine()
    return _default_engine
