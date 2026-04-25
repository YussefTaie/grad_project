from __future__ import annotations

from datetime import datetime
from typing import Optional

from db import (
    sync_get_action_control,
    sync_insert_action,
    sync_insert_alert,
    sync_insert_blocked_ip,
    sync_remove_blocked_ip,
    sync_upsert_action_control,
    sync_upsert_host,
    sync_update_host_status,
)


ACTION_PRIORITY = {"auto": 1, "manual": 2}


def default_action_state(target: str) -> dict:
    return {
        "target": target,
        "is_blocked": False,
        "is_isolated": False,
        "is_whitelisted": False,
        "is_quarantined": False,
        "last_action": "NONE",
        "reason": "",
        "source": "manual",
        "confidence": 0.0,
        "trigger": "manual",
        "updated_at": None,
    }


def get_action_state(target: str) -> dict:
    return sync_get_action_control(target) or default_action_state(target)


def _priority_of(source: str) -> int:
    return ACTION_PRIORITY.get((source or "").lower(), 0)


def execute_host_action(
    *,
    action: str,
    target: str,
    reason: str,
    source: str,
    confidence: float = 0.0,
    trigger: Optional[str] = None,
) -> tuple[dict, int]:
    action_upper = (action or "").upper().strip()
    normalized_target = (target or "").strip()
    normalized_source = (source or "manual").lower().strip()
    normalized_trigger = (trigger or normalized_source).lower().strip()
    normalized_reason = (reason or f"{normalized_source.title()} {action_upper.lower()} action").strip()

    if not normalized_target:
        return {"error": "Target is required"}, 400

    if action_upper not in {"BLOCK", "ISOLATE", "WHITELIST", "UNBLOCK", "UNISOLATE"}:
        return {"error": f"Unsupported action: {action}"}, 400

    existing = get_action_state(normalized_target)
    if (
        existing.get("last_action") not in (None, "NONE")
        and _priority_of(normalized_source) < _priority_of(existing.get("source", "manual"))
    ):
        return {
            "status": "skipped",
            "action": action_upper.lower(),
            "target": normalized_target,
            "message": "Manual action override is active",
            "state": existing,
            "log": {
                "action": action_upper.lower(),
                "target": normalized_target,
                "timestamp": datetime.utcnow().isoformat(),
                "source": normalized_source,
            },
        }, 200

    host_status = "CLEAN"
    alert_type = None
    alert_message = None

    if action_upper == "BLOCK":
        sync_insert_blocked_ip(normalized_target, normalized_reason)
        host_status = "COMPROMISED"
        alert_type = "BLOCK"
        alert_message = f"Simulated firewall block for {normalized_target}: {normalized_reason}"
        message = "Host blocked successfully"
    elif action_upper == "ISOLATE":
        sync_insert_blocked_ip(normalized_target, normalized_reason)
        host_status = "ISOLATED"
        alert_type = "MALWARE"
        alert_message = f"Simulated host isolation for {normalized_target}: {normalized_reason}"
        message = "Host isolated successfully"
    elif action_upper == "WHITELIST":
        sync_remove_blocked_ip(normalized_target)
        host_status = "CLEAN"
        message = "Host whitelisted successfully"
    elif action_upper == "UNBLOCK":
        sync_remove_blocked_ip(normalized_target)
        host_status = "CLEAN"
        message = "Host unblocked successfully"
    else:
        sync_remove_blocked_ip(normalized_target)
        host_status = "CLEAN"
        message = "Host removed from isolation successfully"

    sync_upsert_host(normalized_target, host_status)
    sync_update_host_status(normalized_target, host_status)

    if alert_type and alert_message:
        sync_insert_alert(normalized_target, alert_type, alert_message)

    stored_action = "WHITELIST" if action_upper == "WHITELIST" else action_upper
    sync_upsert_action_control(
        normalized_target,
        action=stored_action,
        reason=normalized_reason,
        source=normalized_source,
        confidence=confidence,
        trigger=normalized_trigger,
    )
    sync_insert_action(
        normalized_target,
        stored_action,
        normalized_reason,
        normalized_source,
        confidence,
    )

    state = get_action_state(normalized_target)
    return {
        "status": "success",
        "action": action_upper.lower(),
        "target": normalized_target,
        "message": message,
        "state": state,
        "log": {
            "action": action_upper.lower(),
            "target": normalized_target,
            "timestamp": state.get("updated_at") or datetime.utcnow().isoformat(),
            "source": normalized_source,
            "reason": normalized_reason,
            "confidence": confidence,
            "trigger": normalized_trigger,
        },
    }, 200
