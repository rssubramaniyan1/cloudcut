"""
CloudCut MCP Server v3 — Trust Patch
═════════════════════════════════════
Scan → Analyze → Report → Fix (3 safe classes only) → Verify → Summary

Trust controls:
  - SAFE_FIX_ALLOWLIST: only orphaned_ebs, unassociated_eip, old_snapshot
  - Dry-run returns "DRY RUN — no changes made" with before/after state
  - Every action (dry-run, confirmed, refused, failed) is logged to ~/.cloudcut/action_log.jsonl
  - Confidence floor: 80%. Risk gate: blocks "high".
  - Everything else: report + CLI command, no executable path.
"""
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from mcp.server.fastmcp import FastMCP, Context
from pydantic import BaseModel, Field, ConfigDict

from cloudcut.collectors.aws_inventory import AWSCollector
from cloudcut.engine.rules import run_all_checks
from cloudcut.engine.allowlist import (
    SAFE_FIX_ALLOWLIST, can_fix, build_dry_run_response, _get_fix_command,
)
from cloudcut.engine.action_log import (
    log_dry_run, log_confirmed, log_failed, log_refused,
    get_session_log, get_total_savings,
)
from cloudcut.models.schemas import (
    Finding, ConfidenceBand, ActionClass, ResourceType,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cloudcut_mcp")

TRANSPORT = os.environ.get("CLOUDCUT_TRANSPORT", "stdio")  # "stdio" or "http"


@asynccontextmanager
async def cloudcut_lifespan():
    yield {"collector": None, "resources": [], "usage": [], "findings": []}

mcp = FastMCP(
    "cloudcut_mcp",
    lifespan=cloudcut_lifespan,
    host="0.0.0.0" if TRANSPORT == "http" else "127.0.0.1",
    port=int(os.environ.get("PORT", "8000")),
)


# ═══ HEALTH / ROOT ROUTE ═══

@mcp.custom_route("/", methods=["GET"])
async def root(request):
    from starlette.responses import JSONResponse
    return JSONResponse({
        "service": "cloudcut_mcp",
        "status": "ok",
        "version": "0.3.0",
        "transport": TRANSPORT,
        "mcp_endpoint": "/mcp",
        "landing_page": "https://cloudcut.dev",
    })


# ═══ DIAGNOSTIC TOOLS ═══

class InventoryInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    role_arn: Optional[str] = Field(default=None, description="Cross-account IAM role ARN. Omit to use local AWS credentials.")
    regions: list[str] = Field(default=["ap-south-1"])

@mcp.tool(name="cloudcut_inventory_aws", annotations={"title": "Inventory AWS Resources", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
async def inventory_aws(params: InventoryInput, ctx: Context) -> str:
    """Collect AWS resource inventory and 30-day usage metrics via cross-account IAM role. Scans EC2, EBS, EIP, RDS, ECS, Lambda, NAT Gateway."""
    state = ctx.request_context.lifespan_state
    try:
        collector = AWSCollector(role_arn=params.role_arn, regions=params.regions)
        await ctx.report_progress(0.3, f"Scanning {len(params.regions)} region(s)...")
        resources, usage = collector.collect_all()
        state["collector"] = collector
        state["resources"] = resources
        state["usage"] = usage
        by_type = {}
        for r in resources:
            by_type[r.resource_type.value] = by_type.get(r.resource_type.value, 0) + 1
        return json.dumps({"total_resources": len(resources), "by_type": by_type, "regions": params.regions}, indent=2)
    except Exception as e:
        return f"Error: {_diagnose_error(e)}"

class CostInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role_arn: Optional[str] = Field(default=None)
    days: int = Field(default=30, ge=7, le=90)
    regions: list[str] = Field(default=["ap-south-1"])

@mcp.tool(name="cloudcut_analyze_costs", annotations={"title": "Analyze AWS Costs", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
async def analyze_costs(params: CostInput, ctx: Context) -> str:
    """Pull Cost Explorer data. Returns top spending services with dollar amounts."""
    state = ctx.request_context.lifespan_state
    collector = state.get("collector")
    if not collector and params.role_arn:
        collector = AWSCollector(role_arn=params.role_arn, regions=params.regions)
        state["collector"] = collector
    elif not collector:
        return "Error: Call cloudcut_inventory_aws first, or provide role_arn."
    cost_data = collector.collect_costs(days=params.days)
    if not cost_data:
        return "Error: Could not retrieve cost data."
    svc_totals = {}
    for period in cost_data.get("ResultsByTime", []):
        for g in period.get("Groups", []):
            s = g["Keys"][0]
            svc_totals[s] = svc_totals.get(s, 0) + float(g["Metrics"]["BlendedCost"]["Amount"])
    sorted_s = sorted(svc_totals.items(), key=lambda x: -x[1])
    total = sum(v for _, v in sorted_s)
    return json.dumps({"period_days": params.days, "total_spend": round(total, 2), "estimated_monthly": round(total / params.days * 30, 2), "top_services": [{"service": s, "spend": round(a, 2)} for s, a in sorted_s if a > 0.01]}, indent=2)

class WasteCheckInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role_arn: Optional[str] = Field(default=None)
    regions: list[str] = Field(default=["ap-south-1"])
    min_confidence: float = Field(default=0.65, ge=0.0, le=1.0)

@mcp.tool(name="cloudcut_run_waste_checks", annotations={"title": "Run Waste Checks", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
async def run_waste_checks(params: WasteCheckInput, ctx: Context) -> str:
    """Run 5 deterministic waste checks. Each finding includes: resource ID, savings, confidence, CLI command, and whether it's safe-fixable."""
    state = ctx.request_context.lifespan_state
    resources = state.get("resources", [])
    usage = state.get("usage", [])
    if not resources:
        if params.role_arn:
            collector = AWSCollector(role_arn=params.role_arn, regions=params.regions)
            resources, usage = collector.collect_all()
            state["resources"] = resources
            state["usage"] = usage
        else:
            return "Error: No inventory. Call cloudcut_inventory_aws first."
    findings = run_all_checks(resources, usage)
    findings = [f for f in findings if f.confidence_score >= params.min_confidence]
    state["findings"] = findings
    total = sum(f.recommendation.estimated_monthly_savings for f in findings)
    return json.dumps({
        "total_findings": len(findings),
        "total_monthly_savings": round(total, 2),
        "safe_fixable": len([f for f in findings if f.finding_type.value in SAFE_FIX_ALLOWLIST]),
        "report_only": len([f for f in findings if f.finding_type.value not in SAFE_FIX_ALLOWLIST]),
        "findings": [{
            "priority": i + 1,
            "finding_id": f.finding_id,
            "title": f.title,
            "resource_id": f.resource_id,
            "severity": f.severity.value,
            "action": f.recommendation.action_class.value,
            "monthly_savings": f.recommendation.estimated_monthly_savings,
            "confidence": f"{f.confidence_score:.0%}",
            "risk": f.recommendation.risk_level.value,
            "safe_fixable": f.finding_type.value in SAFE_FIX_ALLOWLIST,
            "summary": f.summary,
            "cli_command": _get_fix_command(f),
        } for i, f in enumerate(findings)],
    }, indent=2)

class ReportInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: str = Field(default="markdown", pattern="^(markdown|json)$")

@mcp.tool(name="cloudcut_generate_report", annotations={"title": "Generate Report", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def generate_report(params: ReportInput, ctx: Context) -> str:
    """Generate diagnostic report. Findings grouped by: safe-fixable vs report-only. Each includes CLI command."""
    state = ctx.request_context.lifespan_state
    findings = state.get("findings", [])
    if not findings:
        return "Error: No findings. Call cloudcut_run_waste_checks first."
    total = sum(f.recommendation.estimated_monthly_savings for f in findings)
    nr = len(state.get("resources", []))
    safe = [f for f in findings if f.finding_type.value in SAFE_FIX_ALLOWLIST]
    report_only = [f for f in findings if f.finding_type.value not in SAFE_FIX_ALLOWLIST]

    if params.format == "json":
        return json.dumps({"resources": nr, "findings": len(findings), "savings": round(total, 2)}, indent=2)

    lines = [
        "# CloudCut — AWS Cost Diagnostic Report\n",
        f"**Resources scanned:** {nr}",
        f"**Findings:** {len(findings)} ({len(safe)} safe-fixable, {len(report_only)} report-only)",
        f"**Monthly savings:** ${total:,.2f}",
        f"**Annual savings:** ${total * 12:,.2f}\n",
    ]
    if safe:
        safe_sav = sum(f.recommendation.estimated_monthly_savings for f in safe)
        lines.append(f"## Safe-Fixable Findings (${safe_sav:,.2f}/mo)\n")
        lines.append("*These can be auto-fixed with `cloudcut_fix_finding`. Low risk, high confidence.*\n")
        for f in safe:
            lines.extend(_format_finding_md(f))
    if report_only:
        ro_sav = sum(f.recommendation.estimated_monthly_savings for f in report_only)
        lines.append(f"## Report-Only Findings (${ro_sav:,.2f}/mo)\n")
        lines.append("*These require manual review. CLI commands provided below.*\n")
        for f in report_only:
            lines.extend(_format_finding_md(f))
    return "\n".join(lines)


# ═══ REMEDIATION (TRUST-PATCHED) ═══

class FixInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_id: str = Field(..., description="finding_id from waste check results")
    confirm: bool = Field(default=False, description="Set true only after reviewing dry-run output and getting user approval.")
    snapshot_before_delete: bool = Field(default=True, description="Create safety snapshot before deleting EBS (recommended)")

@mcp.tool(name="cloudcut_fix_finding", annotations={"title": "Fix Finding (Safe Classes Only)", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True})
async def fix_finding(params: FixInput, ctx: Context) -> str:
    """Fix a waste finding. ONLY 3 safe classes: orphaned EBS, unused EIP, old snapshots.

    Everything else is refused with a CLI command to run manually.

    When confirm=false: returns DRY RUN with exact before/after state. No changes made.
    When confirm=true: executes the fix, logs the action, returns result.

    Every call (dry-run, confirmed, refused, failed) is logged to ~/.cloudcut/action_log.jsonl.
    """
    state = ctx.request_context.lifespan_state
    findings = state.get("findings", [])
    collector = state.get("collector")

    if not collector:
        return "Error: No active session. Call cloudcut_inventory_aws first."

    finding = next((f for f in findings if f.finding_id == params.finding_id), None)
    if not finding:
        return f"Error: Finding '{params.finding_id}' not found."

    # Check allowlist
    allowed, reason = can_fix(finding)
    if not allowed:
        log_refused(finding.finding_id, finding.resource_id, finding.finding_type.value, reason,
                    cli_command=_get_fix_command(finding),
                    confidence=finding.confidence_score,
                    risk_level=finding.recommendation.risk_level.value)
        return json.dumps({
            "status": "REFUSED — not in safe fix allowlist",
            "finding_id": finding.finding_id,
            "resource_id": finding.resource_id,
            "reason": reason,
            "cli_command": _get_fix_command(finding),
            "message": "Use the CLI command above to fix this manually.",
        }, indent=2)

    # Dry-run
    if not params.confirm:
        dry_run = build_dry_run_response(finding)
        log_dry_run(
            finding.finding_id, finding.resource_id, finding.finding_type.value,
            finding.recommendation.action_class.value,
            dry_run["before_state"], dry_run["expected_after_state"],
            finding.recommendation.estimated_monthly_savings,
        )
        return json.dumps(dry_run, indent=2)

    # Execute
    before = build_dry_run_response(finding)["before_state"]
    try:
        result, snapshot_id = await _execute_fix(finding, collector, params.snapshot_before_delete, ctx)
        after = _build_confirmed_after(finding, result, snapshot_id)
        log_confirmed(
            finding.finding_id, finding.resource_id, finding.finding_type.value,
            finding.recommendation.action_class.value,
            before, after, finding.recommendation.estimated_monthly_savings,
            snapshot_id=snapshot_id,
        )
        return json.dumps({
            "status": "COMPLETED",
            "finding_id": finding.finding_id,
            "resource_id": finding.resource_id,
            "action_taken": result,
            "before_state": before,
            "after_state": after,
            "monthly_savings": finding.recommendation.estimated_monthly_savings,
            "safety_snapshot": snapshot_id,
            "logged_to": "~/.cloudcut/action_log.jsonl",
        }, indent=2)
    except Exception as e:
        log_failed(
            finding.finding_id, finding.resource_id, finding.finding_type.value,
            finding.recommendation.action_class.value,
            before, str(e), finding.recommendation.estimated_monthly_savings,
        )
        return json.dumps({
            "status": "FAILED",
            "resource_id": finding.resource_id,
            "error": str(e),
            "before_state": before,
            "after_state": {"state": "UNCHANGED — fix failed"},
            "rollback": finding.recommendation.rollback,
        }, indent=2)


# ═══ VERIFICATION ═══

class VerifyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    check_type: str = Field(default="all", pattern="^(ecs|rds|url|all)$")
    url: Optional[str] = Field(default=None)
    region: str = Field(default="ap-south-1")

@mcp.tool(name="cloudcut_verify_service", annotations={"title": "Verify Services Healthy", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
async def verify_service(params: VerifyInput, ctx: Context) -> str:
    """Check ECS, RDS, and HTTP endpoints are healthy after fixes."""
    state = ctx.request_context.lifespan_state
    collector = state.get("collector")
    results = {"checks": [], "overall": "healthy"}
    if params.check_type in ("ecs", "all") and collector:
        try:
            ecs = collector._client("ecs", params.region)
            for ca in ecs.list_clusters().get("clusterArns", []):
                svcs = ecs.list_services(cluster=ca).get("serviceArns", [])
                if svcs:
                    for svc in ecs.describe_services(cluster=ca, services=svcs[:10]).get("services", []):
                        ok = svc["runningCount"] >= svc["desiredCount"] > 0
                        results["checks"].append({"type": "ecs", "service": svc["serviceName"], "desired": svc["desiredCount"], "running": svc["runningCount"], "status": "healthy" if ok else "degraded"})
                        if not ok: results["overall"] = "degraded"
        except Exception as e:
            results["checks"].append({"type": "ecs", "error": str(e)})
    if params.check_type in ("rds", "all") and collector:
        try:
            for db in collector._client("rds", params.region).describe_db_instances().get("DBInstances", []):
                ok = db["DBInstanceStatus"] == "available"
                results["checks"].append({"type": "rds", "instance": db["DBInstanceIdentifier"], "status": "healthy" if ok else db["DBInstanceStatus"]})
        except Exception as e:
            results["checks"].append({"type": "rds", "error": str(e)})
    if params.check_type in ("url", "all") and params.url:
        try:
            import urllib.request
            with urllib.request.urlopen(urllib.request.Request(params.url, headers={"User-Agent": "CloudCut/1.0"}), timeout=10) as r:
                results["checks"].append({"type": "url", "url": params.url, "status_code": r.getcode(), "status": "healthy" if r.getcode() < 400 else "unhealthy"})
        except Exception as e:
            results["checks"].append({"type": "url", "url": params.url, "status": "unreachable", "error": str(e)})
            results["overall"] = "error"
    return json.dumps(results, indent=2)


# ═══ SESSION SUMMARY ═══

@mcp.tool(name="cloudcut_show_savings_summary", annotations={"title": "Savings Summary", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def show_savings_summary(ctx: Context) -> str:
    """Show all actions from the action log: dry-runs, confirmed fixes, refused, failed. Total savings calculated from confirmed fixes only."""
    entries = get_session_log()
    if not entries:
        return "No actions logged yet. Run cloudcut_fix_finding to start."
    confirmed = [e for e in entries if e["outcome"] == "success"]
    refused = [e for e in entries if e["outcome"] == "refused"]
    dry_runs = [e for e in entries if e["outcome"] == "preview"]
    failed = [e for e in entries if e["outcome"] == "failed"]
    total_saved = sum(e["savings_estimate_monthly"] for e in confirmed)
    lines = ["# CloudCut — Action Log Summary\n"]
    if confirmed:
        lines.append(f"## Confirmed Fixes ({len(confirmed)})\n")
        for e in confirmed:
            snap = f" (backup: {e['snapshot_id']})" if e.get("snapshot_id") else ""
            lines.append(f"- ✅ `{e['resource_id']}` — {e['finding_type']} — **${e['savings_estimate_monthly']}/mo**{snap}")
        lines.extend([f"\n**Monthly savings: ${total_saved:,.2f}**", f"**Annual savings: ${total_saved * 12:,.2f}**\n"])
    if dry_runs:
        lines.append(f"## Dry Runs ({len(dry_runs)})\n")
        for e in dry_runs:
            lines.append(f"- 👁️ `{e['resource_id']}` — {e['finding_type']} — ${e['savings_estimate_monthly']}/mo (no changes)")
    if refused:
        lines.append(f"\n## Refused ({len(refused)})\n")
        for e in refused:
            lines.append(f"- ⛔ `{e['resource_id']}` — {e.get('error', 'not in allowlist')}")
    if failed:
        lines.append(f"\n## Failed ({len(failed)})\n")
        for e in failed:
            lines.append(f"- ❌ `{e['resource_id']}` — {e.get('error', 'unknown')}")
    return "\n".join(lines)


# ═══ PHASE 2 STUBS ═══

class CodeScanInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repo_path: str = Field(...)
    branch: str = Field(default="main")

@mcp.tool(name="cloudcut_scan_code_intent", annotations={"title": "[Phase 2] Scan Code Intent", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def scan_code_intent(params: CodeScanInput) -> str:
    """[Phase 2] Scan repo for AWS service usage. Not yet implemented."""
    return json.dumps({"status": "not_implemented", "message": "Phase 2. Use cloudcut_run_waste_checks."})

@mcp.tool(name="cloudcut_compare_code_vs_aws", annotations={"title": "[Phase 2] Code vs AWS Drift", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def compare_code_vs_aws(params: CodeScanInput) -> str:
    """[Phase 2] Compare code intent vs AWS inventory. Not yet implemented."""
    return json.dumps({"status": "not_implemented", "message": "Phase 2. Use cloudcut_run_waste_checks."})


# ═══ HELPERS ═══

def _format_finding_md(f: Finding) -> list[str]:
    sev = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}.get(f.severity.value, "⚪")
    fixable = "✅ Safe-fixable" if f.finding_type.value in SAFE_FIX_ALLOWLIST else "📋 Manual"
    lines = [
        f"### {sev} {f.title}",
        f"- **Resource:** `{f.resource_id}`",
        f"- **Savings:** ${f.recommendation.estimated_monthly_savings}/mo",
        f"- **Confidence:** {f.confidence_score:.0%} ({f.confidence_band.value})",
        f"- **Risk:** {f.recommendation.risk_level.value} | **Fix:** {fixable}",
        f"\n{f.summary}\n",
    ]
    cmd = _get_fix_command(f)
    if cmd:
        lines.append(f"```bash\n{cmd}\n```\n")
    if f.recommendation.rollback:
        lines.append(f"**Rollback:** {f.recommendation.rollback}\n")
    lines.append("---\n")
    return lines


async def _execute_fix(finding, collector, snapshot_first, ctx) -> tuple[str, Optional[str]]:
    """Execute a safe fix. Returns (result_message, snapshot_id_or_none)."""
    region = finding.region  # derive from finding, not hardcoded
    rid = finding.resource_id
    snapshot_id = None

    if finding.finding_type.value == "orphaned_ebs":
        ec2 = collector._client("ec2", region)
        if snapshot_first:
            await ctx.report_progress(0.3, f"Creating safety snapshot of {rid}...")
            snap = ec2.create_snapshot(VolumeId=rid, Description="CloudCut safety backup before delete")
            snapshot_id = snap["SnapshotId"]
            await ctx.report_progress(0.5, f"Waiting for snapshot {snapshot_id}...")
            ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[snapshot_id])
        await ctx.report_progress(0.8, f"Deleting volume {rid}...")
        ec2.delete_volume(VolumeId=rid)
        return f"Volume {rid} deleted in {region}.", snapshot_id

    elif finding.finding_type.value == "unassociated_eip":
        await ctx.report_progress(0.5, f"Releasing EIP {rid}...")
        collector._client("ec2", region).release_address(AllocationId=rid)
        return f"EIP {rid} released in {region}.", None

    elif finding.finding_type.value == "old_snapshot":
        # TARGETED deletion: only delete snapshot IDs from the finding metadata
        snap_ids = finding.metadata.get("snapshot_ids", [])
        if not snap_ids:
            raise ValueError("No snapshot IDs in finding metadata. Cannot execute blind deletion.")
        ec2 = collector._client("ec2", region)
        deleted = []
        failed = []
        for sid in snap_ids:
            try:
                await ctx.report_progress(len(deleted) / len(snap_ids), f"Deleting {sid}...")
                ec2.delete_snapshot(SnapshotId=sid)
                deleted.append(sid)
            except Exception as e:
                failed.append({"snapshot_id": sid, "error": str(e)})
        result = f"Deleted {len(deleted)}/{len(snap_ids)} snapshots in {region}."
        if failed:
            result += f" Failed: {len(failed)}."
        return result, None

    raise ValueError(f"No executor for {finding.finding_type.value}")


def _build_confirmed_after(finding, result: str, snapshot_id: Optional[str]) -> dict:
    """Build explicit after-state per action type for confirmed fixes."""
    ft = finding.finding_type.value

    if ft == "orphaned_ebs":
        return {
            "resource": finding.resource_id,
            "state": "DELETED",
            "region": finding.region,
            "billing": "$0/mo",
            "safety_snapshot": snapshot_id,
            "detail": result,
        }
    elif ft == "unassociated_eip":
        return {
            "resource": finding.resource_id,
            "state": "RELEASED",
            "region": finding.region,
            "billing": "$0/mo",
            "detail": result,
        }
    elif ft == "old_snapshot":
        snap_ids = finding.metadata.get("snapshot_ids", [])
        return {
            "resource": finding.resource_id,
            "state": "DELETED (targeted)",
            "region": finding.region,
            "snapshots_targeted": len(snap_ids),
            "detail": result,
        }
    return {"state": "MODIFIED", "detail": result}


def _diagnose_error(e):
    msg = str(e)
    if "AccessDenied" in msg: return "IAM role lacks permissions."
    if "ExpiredToken" in msg: return "Session expired."
    return f"Error: {msg[:200]}"


if __name__ == "__main__":
    if TRANSPORT == "http":
        logger.info("Starting CloudCut MCP server (streamable-http on port %s)", mcp.settings.port)
        mcp.run(transport="streamable-http")
    else:
        logger.info("Starting CloudCut MCP server (stdio)")
        mcp.run(transport="stdio")
