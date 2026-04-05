"""
CloudCut — Safe Fix Allowlist & Dry-Run Builder
════════════════════════════════════════════════
Three fixable classes. Everything else is report-only.
This file IS the trust boundary. If it's not in SAFE_FIX_ALLOWLIST,
it cannot be executed, period.
"""
from cloudcut.models.schemas import Finding, FindingType, ActionClass


# ─── THE ALLOWLIST ───
# Only these three finding types can be auto-fixed.
# Everything else returns a CLI command in the report.
# To add a new fixable class, add it here AND in _execute_fix.
# This is intentionally a small, boring, conservative list.

SAFE_FIX_ALLOWLIST: set[str] = {
    FindingType.orphaned_ebs.value,      # delete unattached EBS volume
    FindingType.unassociated_eip.value,   # release idle Elastic IP
    FindingType.old_snapshot.value,       # delete specific snapshots identified by ID in finding metadata
}

# Minimum confidence to allow execution
MIN_FIX_CONFIDENCE = 0.80

# These risk levels block execution regardless of finding type
BLOCKED_RISK_LEVELS = {"high"}


def can_fix(finding: Finding) -> tuple[bool, str]:
    """Check if a finding is eligible for automated fix.

    Returns:
        (allowed: bool, reason: str)
    """
    if finding.finding_type.value not in SAFE_FIX_ALLOWLIST:
        return False, (
            f"Finding type '{finding.finding_type.value}' is not in the safe fix allowlist. "
            f"Only orphaned EBS, unused EIP, and old snapshots can be auto-fixed. "
            f"Use the CLI command in the report to fix this manually."
        )

    if finding.confidence_score < MIN_FIX_CONFIDENCE:
        return False, (
            f"Confidence {finding.confidence_score:.0%} is below the {MIN_FIX_CONFIDENCE:.0%} threshold. "
            f"This finding needs manual review before action."
        )

    if finding.recommendation.risk_level.value in BLOCKED_RISK_LEVELS:
        return False, (
            f"Risk level '{finding.recommendation.risk_level.value}' blocks automated execution. "
            f"Review this finding manually."
        )

    return True, "Eligible for safe fix."


def build_dry_run_response(finding: Finding) -> dict:
    """Build an explicit dry-run response showing exactly what WOULD happen.

    This is returned when confirm=false. It must be unmistakably clear
    that no changes were made.
    """
    before_state = _get_before_state(finding)
    after_state = _get_after_state(finding)

    return {
        "status": "DRY RUN — no changes made",
        "finding_id": finding.finding_id,
        "finding_type": finding.finding_type.value,
        "resource_id": finding.resource_id,
        "action": finding.recommendation.action_class.value,
        "description": finding.summary,
        "before_state": before_state,
        "expected_after_state": after_state,
        "estimated_monthly_savings": finding.recommendation.estimated_monthly_savings,
        "estimated_annual_savings": round(finding.recommendation.estimated_monthly_savings * 12, 2),
        "confidence": f"{finding.confidence_score:.0%} ({finding.confidence_band.value})",
        "risk_level": finding.recommendation.risk_level.value,
        "rollback": finding.recommendation.rollback,
        "cli_command": _get_fix_command(finding),
        "next_step": "To execute: call cloudcut_fix_finding with confirm=true",
    }


def _get_before_state(finding: Finding) -> dict:
    """Describe the current state of the resource."""
    ft = finding.finding_type.value

    if ft == "orphaned_ebs":
        return {
            "resource": finding.resource_id,
            "type": "EBS Volume",
            "state": "available (unattached)",
            "billing": f"${finding.recommendation.estimated_monthly_savings}/mo",
            "evidence": finding.evidence.infra + finding.evidence.cost,
        }
    elif ft == "unassociated_eip":
        return {
            "resource": finding.resource_id,
            "type": "Elastic IP",
            "state": "unassociated (no instance/ENI)",
            "billing": "$3.60/mo",
            "evidence": finding.evidence.infra,
        }
    elif ft == "old_snapshot":
        snap_ids = finding.metadata.get("snapshot_ids", [])
        snap_ages = finding.metadata.get("snapshot_ages", {})
        total_gb = finding.metadata.get("total_gb", 0)
        oldest = max(snap_ages.values()) if snap_ages else "unknown"
        return {
            "resource": finding.resource_id,
            "type": "EBS Snapshots",
            "state": f"{len(snap_ids)} snapshots identified for deletion",
            "snapshot_ids": snap_ids,
            "snapshot_count": len(snap_ids),
            "total_gb": total_gb,
            "oldest_age_days": oldest,
            "billing": f"${finding.recommendation.estimated_monthly_savings}/mo",
            "evidence": finding.evidence.infra + finding.evidence.cost,
        }
    return {
        "resource": finding.resource_id,
        "state": "see evidence",
        "evidence": finding.evidence.infra + finding.evidence.runtime + finding.evidence.cost,
    }


def _get_after_state(finding: Finding) -> dict:
    """Describe the expected state after fix is applied."""
    ft = finding.finding_type.value

    if ft == "orphaned_ebs":
        return {
            "resource": finding.resource_id,
            "state": "DELETED",
            "billing": "$0/mo",
            "note": "Volume data permanently removed. Safety snapshot created first if snapshot_before_delete=true.",
        }
    elif ft == "unassociated_eip":
        return {
            "resource": finding.resource_id,
            "state": "RELEASED",
            "billing": "$0/mo",
            "note": "IP returns to AWS pool. Allocate a new EIP if needed later.",
        }
    elif ft == "old_snapshot":
        snap_ids = finding.metadata.get("snapshot_ids", [])
        return {
            "resource": finding.resource_id,
            "state": "DELETED (targeted)",
            "snapshots_to_delete": snap_ids,
            "snapshot_count": len(snap_ids),
            "billing": "Reduced by ~${:.2f}/mo".format(finding.recommendation.estimated_monthly_savings),
            "note": f"Only these {len(snap_ids)} specific snapshots will be deleted. No other snapshots are affected.",
        }
    return {"state": "See recommendation", "note": "Manual action required."}


def _get_fix_command(finding: Finding) -> str | None:
    """Generate the exact AWS CLI command. Always returned, even for non-fixable findings."""
    rid = finding.resource_id
    r = finding.region  # derive from finding, not hardcoded

    commands = {
        "orphaned_ebs": f"aws ec2 delete-volume --volume-id {rid} --region {r}",
        "unassociated_eip": f"aws ec2 release-address --allocation-id {rid} --region {r}",
        "old_snapshot": _build_snapshot_delete_command(finding),
        "idle_ec2": (
            f"# Stop (reversible):\n"
            f"aws ec2 stop-instances --instance-ids {rid} --region {r}\n"
            f"# Or terminate (permanent):\n"
            f"aws ec2 terminate-instances --instance-ids {rid} --region {r}"
        ),
        "gpu_non_prod": f"aws ec2 terminate-instances --instance-ids {rid} --region {r}",
        "oversized_rds": (
            f"aws rds modify-db-instance --db-instance-identifier {rid} "
            f"--db-instance-class db.t3.micro --apply-immediately --region {r}"
        ),
        "nat_gateway_anomaly": (
            f"# Review NAT Gateway usage, consider VPC endpoints:\n"
            f"aws ec2 describe-nat-gateways --nat-gateway-ids {rid} --region {r}"
        ),
    }
    return commands.get(finding.finding_type.value)


def _build_snapshot_delete_command(finding: Finding) -> str:
    """Build targeted snapshot delete commands using exact IDs from finding metadata."""
    snap_ids = finding.metadata.get("snapshot_ids", [])
    r = finding.region
    if not snap_ids:
        return (
            f"aws ec2 describe-snapshots --owner-ids self --region {r} "
            f"--query 'sort_by(Snapshots,&StartTime)[*].[SnapshotId,VolumeSize,StartTime]' --output table"
        )
    lines = [f"# Delete {len(snap_ids)} specific snapshots:"]
    for sid in snap_ids:
        lines.append(f"aws ec2 delete-snapshot --snapshot-id {sid} --region {r}")
    return "\n".join(lines)
