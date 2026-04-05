"""
CloudCut — FastAPI Application
POST /diagnose → triggers async pipeline → poll /status → GET /report
"""
import logging
import uuid
from datetime import datetime

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from cloudcut.models.schemas import (
    DiagnosticRequest, DiagnosticResponse, DiagnosticStatus, Finding,
)
from cloudcut.collectors.aws_inventory import AWSCollector
from cloudcut.engine.rules import run_all_checks

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="CloudCut",
    description="Code-aware AWS cost diagnostics",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store (replace with PostgreSQL in production)
diagnostics: dict[str, dict] = {}


@app.post("/diagnose", response_model=DiagnosticStatus)
async def start_diagnostic(req: DiagnosticRequest, bg: BackgroundTasks):
    """Start an async diagnostic pipeline."""
    diag_id = f"diag_{uuid.uuid4().hex[:12]}"

    diagnostics[diag_id] = {
        "status": "collecting",
        "progress_pct": 0,
        "current_step": "Assuming IAM role...",
        "findings_so_far": 0,
        "request": req,
        "result": None,
        "error": None,
    }

    bg.add_task(_run_pipeline, diag_id, req)

    return DiagnosticStatus(
        diagnostic_id=diag_id,
        status="collecting",
        progress_pct=0,
        current_step="Assuming IAM role...",
    )


@app.get("/status/{diag_id}", response_model=DiagnosticStatus)
async def get_status(diag_id: str):
    """Poll diagnostic progress."""
    if diag_id not in diagnostics:
        raise HTTPException(404, "Diagnostic not found")

    d = diagnostics[diag_id]
    return DiagnosticStatus(
        diagnostic_id=diag_id,
        status=d["status"],
        progress_pct=d["progress_pct"],
        current_step=d["current_step"],
        findings_so_far=d["findings_so_far"],
    )


@app.get("/report/{diag_id}", response_model=DiagnosticResponse)
async def get_report(diag_id: str):
    """Retrieve completed diagnostic report."""
    if diag_id not in diagnostics:
        raise HTTPException(404, "Diagnostic not found")

    d = diagnostics[diag_id]
    if d["status"] != "complete":
        raise HTTPException(202, f"Diagnostic still in progress: {d['status']}")
    if d["error"]:
        raise HTTPException(500, f"Diagnostic failed: {d['error']}")

    return d["result"]


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


# ─── Background Pipeline ───

async def _run_pipeline(diag_id: str, req: DiagnosticRequest):
    """The actual diagnostic pipeline — runs in background."""
    d = diagnostics[diag_id]

    try:
        # Step 1: Collect AWS inventory
        d["status"] = "collecting"
        d["current_step"] = "Scanning AWS resources..."
        d["progress_pct"] = 10

        collector = AWSCollector(
            role_arn=req.role_arn,
            regions=req.regions,
        )

        resources, usage = collector.collect_all()
        d["progress_pct"] = 40
        d["current_step"] = f"Found {len(resources)} resources. Pulling cost data..."

        # Step 2: Cost Explorer
        cost_data = collector.collect_costs(days=30)
        d["progress_pct"] = 55

        # Step 3: Run checks
        d["status"] = "analyzing"
        d["current_step"] = "Running 9 diagnostic checks..."
        d["progress_pct"] = 60

        findings = run_all_checks(resources, usage)
        d["findings_so_far"] = len(findings)
        d["progress_pct"] = 85

        # Step 4: Generate report
        d["status"] = "generating"
        d["current_step"] = "Building report..."
        d["progress_pct"] = 90

        total_savings = sum(
            f.recommendation.estimated_monthly_savings for f in findings
        )

        # Extract account ID from role ARN
        account_id = req.role_arn.split(":")[4] if ":" in req.role_arn else "unknown"

        result = DiagnosticResponse(
            diagnostic_id=diag_id,
            account_id=account_id,
            regions=req.regions,
            total_resources_scanned=len(resources),
            total_findings=len(findings),
            total_monthly_savings=round(total_savings, 2),
            total_annual_savings=round(total_savings * 12, 2),
            findings=findings,
        )

        d["result"] = result
        d["status"] = "complete"
        d["progress_pct"] = 100
        d["current_step"] = "Report ready"

        logger.info(
            f"Diagnostic {diag_id} complete: "
            f"{len(resources)} resources, {len(findings)} findings, "
            f"${total_savings:.2f}/mo savings"
        )

    except Exception as e:
        logger.error(f"Pipeline {diag_id} failed: {e}")
        d["status"] = "error"
        d["error"] = str(e)
        d["current_step"] = f"Error: {str(e)[:100]}"
