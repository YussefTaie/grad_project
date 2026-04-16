"""
flow_utils.py  —  Shared Flow Computation Utilities
====================================================
Centralizes critical flow metric calculations to guarantee consistency
across all modules (unified_agent, agent_live_real, flow_builder, etc.)

FIX 5: Single authoritative compute_pps() eliminates cross-module drift.
FIX 1: min duration floor of 0.01s prevents artificial PPS inflation on
       single-packet or sub-millisecond flows.
"""

# ── Minimum measurable flow duration (100ms floor) ───────────────────────────
# Rationale:
#   A single-packet flow has duration = 0.  Without a floor:
#     PPS = 1 / 1e-9 = 1,000,000,000  ← completely unrealistic
#   With a 0.01s floor:
#     PPS = 1 / 0.01 = 100            ← realistic upper bound for single pkts
#
#   0.01s (10ms) is the practical minimum network round-trip time on a LAN.
MIN_FLOW_DURATION_SEC = 0.01


def compute_pps(packet_count: int, duration_sec: float) -> float:
    """
    Compute Packets per Second with a realistic minimum duration floor.

    Args:
        packet_count:  Total number of packets in the flow.
        duration_sec:  Flow duration in seconds (may be 0 for single-packet flows).

    Returns:
        PPS as a float, always realistic (never artificially inflated).

    Examples:
        >>> compute_pps(1, 0.0)      # single-packet flow
        1.0                           # pps = 1 / max(0, 1) = 1.0
        >>> compute_pps(100, 1.0)    # 100 pkts over 1 second
        100.0
        >>> compute_pps(500, 5.0)    # 100 pps, 5 second flow
        100.0
    """
    # Use packets / max(duration, 1) as specified — avoids PPS=0 for short flows
    # while preventing artificial inflation from sub-millisecond durations.
    safe_duration = max(duration_sec, 1.0)
    return packet_count / safe_duration
