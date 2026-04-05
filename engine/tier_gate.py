"""
CloudCut — Tier Gate
════════════════════
Controls what the MCP returns based on free vs paid.

Free: top 3 findings, safe-fix for those 3, markdown report.
Paid ($19): all findings, all safe-fixes, downloadable report.

The gate filters output, not analysis. The engine always runs
all checks — the tier controls what the user sees.

License validation: reads CLOUDCUT_LICENSE_KEY from env,
checks against ~/.cloudcut/licenses.json.
"""
import json
import os
import re
import logging
from pathlib import Path

from cloudcut.models.schemas import Finding

logger = logging.getLogger(__name__)


class Tier:
    FREE = "free"
    PAID = "paid"


# Free tier limits
FREE_MAX_FINDINGS = 3
FREE_SHOW_CLI = True          # show CLI commands even in free
FREE_ALLOW_FIX = True         # allow safe-fix for the top 3
FREE_SHOW_SAVINGS_TOTAL = True  # show total potential, not just visible

# License file location
LICENSES_PATH = Path.home() / ".cloudcut" / "licenses.json"


def _load_valid_keys() -> set[str]:
    """Load valid license keys from ~/.cloudcut/licenses.json.

    File format: {"keys": ["CC-XXXX-XXXX-XXXX", ...]}
    """
    if not LICENSES_PATH.exists():
        return set()
    try:
        data = json.loads(LICENSES_PATH.read_text())
        return set(data.get("keys", []))
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load licenses from %s: %s", LICENSES_PATH, e)
        return set()


LICENSE_FORMAT = re.compile(r"^CC-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$")


def validate_license(key: str | None) -> bool:
    """Check if a license key is valid.

    If ~/.cloudcut/licenses.json exists, validates against that list.
    Otherwise, accepts any key matching CC-XXXX-XXXX-XXXX format.
    """
    if not key:
        return False
    key = key.strip()
    valid_keys = _load_valid_keys()
    if valid_keys:
        return key in valid_keys
    return bool(LICENSE_FORMAT.match(key))


def get_current_tier() -> str:
    """Determine the current tier from CLOUDCUT_LICENSE_KEY env var."""
    key = os.environ.get("CLOUDCUT_LICENSE_KEY", "").strip()
    if validate_license(key):
        return Tier.PAID
    return Tier.FREE


def gate_findings(findings: list[Finding], tier: str) -> tuple[list[Finding], dict]:
    """Apply tier gate to findings list.

    Returns:
        (visible_findings, gate_info)

    gate_info includes:
        total_findings: how many exist
        visible_findings: how many are shown
        hidden_findings: how many are behind the paywall
        total_savings: savings across ALL findings (shown even in free)
        visible_savings: savings in visible findings only
        hidden_savings: savings behind the paywall
        upgrade_message: what to show the user
    """
    total = len(findings)
    total_savings = sum(f.recommendation.estimated_monthly_savings for f in findings)

    if tier == Tier.PAID or total <= FREE_MAX_FINDINGS:
        return findings, {
            "tier": tier,
            "total_findings": total,
            "visible_findings": total,
            "hidden_findings": 0,
            "total_savings": round(total_savings, 2),
            "visible_savings": round(total_savings, 2),
            "hidden_savings": 0,
            "upgrade_message": None,
        }

    # Free tier: show top N by priority
    visible = findings[:FREE_MAX_FINDINGS]
    hidden = findings[FREE_MAX_FINDINGS:]
    visible_savings = sum(f.recommendation.estimated_monthly_savings for f in visible)
    hidden_savings = sum(f.recommendation.estimated_monthly_savings for f in hidden)

    return visible, {
        "tier": "free",
        "total_findings": total,
        "visible_findings": len(visible),
        "hidden_findings": len(hidden),
        "total_savings": round(total_savings, 2),
        "visible_savings": round(visible_savings, 2),
        "hidden_savings": round(hidden_savings, 2),
        "upgrade_message": (
            f"Showing top {FREE_MAX_FINDINGS} of {total} findings. "
            f"{len(hidden)} more findings worth ${hidden_savings:.2f}/mo "
            f"available with a license key ($19 at cloudcut.dev)."
        ),
    }


def can_fix_in_tier(finding: Finding, findings: list[Finding], tier: str) -> tuple[bool, str]:
    """Check if a finding can be fixed in the current tier.

    In free tier, only the top 3 findings can be fixed.
    In paid tier, all safe-fixable findings can be fixed.
    """
    if tier == Tier.PAID:
        return True, "Paid tier — all safe-fixable findings are executable."

    # Free: only top 3 are fixable
    top_ids = {f.finding_id for f in findings[:FREE_MAX_FINDINGS]}
    if finding.finding_id in top_ids:
        return True, "Free tier — this finding is in your top 3."

    return False, (
        f"This finding is outside your free tier (top {FREE_MAX_FINDINGS}). "
        f"Get a license key for $19 at cloudcut.dev to unlock all findings and fixes."
    )


def format_gate_footer(gate_info: dict) -> str:
    """Format the upgrade prompt for free tier users."""
    if not gate_info.get("upgrade_message"):
        return ""

    return (
        f"\n{'─' * 50}\n"
        f"💡 {gate_info['upgrade_message']}\n"
        f"   Total potential savings: ${gate_info['total_savings']:.2f}/mo "
        f"(${gate_info['total_savings'] * 12:.2f}/yr)\n"
        f"   → Get license key: cloudcut.dev ($19)\n"
        f"{'─' * 50}"
    )
