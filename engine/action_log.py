"""
CloudCut — Action Log
═════════════════════
Append-only log file used by CloudCut for tracking fix attempts.
Records every interaction: dry-run, confirmed, refused, failed.
One JSON object per line at ~/.cloudcut/action_log.jsonl.
"""
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional


# Log file location — append-only, one JSON object per line
LOG_DIR = os.getenv("CLOUDCUT_LOG_DIR", os.path.expanduser("~/.cloudcut"))
LOG_FILE = os.path.join(LOG_DIR, "action_log.jsonl")


def _ensure_log_dir():
    Path(LOG_DIR).mkdir(parents=True, exist_ok=True)


def log_action(
    finding_id: str,
    resource_id: str,
    finding_type: str,
    action: str,
    mode: str,               # "dry_run" or "confirmed" or "refused"
    before_state: dict,
    after_state: dict,
    outcome: str,             # "success", "failed", "refused", "preview"
    savings_estimate: float,
    error: Optional[str] = None,
    snapshot_id: Optional[str] = None,
    extra: Optional[dict] = None,
) -> dict:
    """Append a single action record to the log.

    Returns the log entry that was written.
    """
    _ensure_log_dir()

    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "finding_id": finding_id,
        "resource_id": resource_id,
        "finding_type": finding_type,
        "action": action,
        "mode": mode,
        "before_state": before_state,
        "after_state": after_state,
        "outcome": outcome,
        "savings_estimate_monthly": savings_estimate,
        "error": error,
        "snapshot_id": snapshot_id,
    }
    if extra:
        entry.update(extra)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, default=str) + "\n")

    return entry


def log_dry_run(finding_id: str, resource_id: str, finding_type: str,
                action: str, before_state: dict, after_state: dict,
                savings_estimate: float) -> dict:
    """Log a dry-run preview."""
    return log_action(
        finding_id=finding_id,
        resource_id=resource_id,
        finding_type=finding_type,
        action=action,
        mode="dry_run",
        before_state=before_state,
        after_state=after_state,
        outcome="preview",
        savings_estimate=savings_estimate,
    )


def log_confirmed(finding_id: str, resource_id: str, finding_type: str,
                  action: str, before_state: dict, after_state: dict,
                  savings_estimate: float, snapshot_id: str = None) -> dict:
    """Log a confirmed fix execution."""
    return log_action(
        finding_id=finding_id,
        resource_id=resource_id,
        finding_type=finding_type,
        action=action,
        mode="confirmed",
        before_state=before_state,
        after_state=after_state,
        outcome="success",
        savings_estimate=savings_estimate,
        snapshot_id=snapshot_id,
    )


def log_failed(finding_id: str, resource_id: str, finding_type: str,
               action: str, before_state: dict, error: str,
               savings_estimate: float) -> dict:
    """Log a failed fix attempt."""
    return log_action(
        finding_id=finding_id,
        resource_id=resource_id,
        finding_type=finding_type,
        action=action,
        mode="confirmed",
        before_state=before_state,
        after_state={"state": "UNCHANGED — fix failed"},
        outcome="failed",
        savings_estimate=savings_estimate,
        error=error,
    )


def log_refused(finding_id: str, resource_id: str, finding_type: str,
                reason: str, cli_command: str = None,
                confidence: float = None, risk_level: str = None) -> dict:
    """Log a refused fix (not in allowlist, low confidence, etc)."""
    return log_action(
        finding_id=finding_id,
        resource_id=resource_id,
        finding_type=finding_type,
        action="refused",
        mode="refused",
        before_state={},
        after_state={},
        outcome="refused",
        savings_estimate=0,
        error=reason,
        extra={
            "suggested_cli_command": cli_command,
            "confidence": confidence,
            "risk_level": risk_level,
        },
    )


def get_session_log() -> list[dict]:
    """Read all log entries. For the summary tool."""
    if not os.path.exists(LOG_FILE):
        return []
    entries = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return entries


def get_total_savings() -> float:
    """Sum savings from all confirmed successful fixes."""
    return sum(
        e["savings_estimate_monthly"]
        for e in get_session_log()
        if e["outcome"] == "success" and e["mode"] == "confirmed"
    )
