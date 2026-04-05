"""
CloudCut — Pydantic Models
All core domain objects: resources, code components, usage, findings, recommendations.
"""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


# ─── Enums ───

class ResourceType(str, Enum):
    ec2_instance = "ec2_instance"
    ebs_volume = "ebs_volume"
    ebs_snapshot = "ebs_snapshot"
    elastic_ip = "elastic_ip"
    rds_instance = "rds_instance"
    ecs_service = "ecs_service"
    lambda_function = "lambda_function"
    nat_gateway = "nat_gateway"
    s3_bucket = "s3_bucket"
    alb = "alb"
    elasticache = "elasticache"
    sqs_queue = "sqs_queue"
    cloudwatch_alarm = "cloudwatch_alarm"


class FindingType(str, Enum):
    orphaned_ebs = "orphaned_ebs"
    unassociated_eip = "unassociated_eip"
    old_snapshot = "old_snapshot"
    idle_ec2 = "idle_ec2"
    gpu_non_prod = "gpu_non_prod"
    zero_invocation_lambda = "zero_invocation_lambda"
    idle_ecs = "idle_ecs"
    oversized_rds = "oversized_rds"
    code_infra_drift = "code_infra_drift"
    nat_gateway_anomaly = "nat_gateway_anomaly"


class ActionClass(str, Enum):
    terminate = "terminate"
    stop_schedule = "stop_schedule"
    rightsize = "rightsize"
    review_architecture = "review_architecture"


class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class ConfidenceBand(str, Enum):
    high = "high"           # 0.85 – 1.00
    medium = "medium"       # 0.65 – 0.84
    low = "low"             # 0.45 – 0.64
    informational = "informational"  # < 0.45


class RecommendationStatus(str, Enum):
    proposed = "proposed"
    accepted = "accepted"
    rejected = "rejected"
    implemented = "implemented"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


# ─── Core Models ───

class AWSResource(BaseModel):
    """What actually exists in AWS."""
    resource_id: str
    resource_type: ResourceType
    region: str
    tags: dict[str, str] = Field(default_factory=dict)
    state: str = ""
    metadata: dict = Field(default_factory=dict)
    collected_at: datetime = Field(default_factory=datetime.utcnow)


class ResourceUsage(BaseModel):
    """What appears active (CloudWatch + Cost Explorer signals)."""
    resource_id: str
    window_days: int = 30
    usage_signals: dict = Field(default_factory=dict)
    # Keys: cpu_avg, memory_avg, network_in_mb, network_out_mb,
    #        invocations, connections_avg, request_count
    cost_signals: dict = Field(default_factory=dict)
    # Keys: monthly_estimated_usd, daily_costs (list)


class CodeComponent(BaseModel):
    """What the repo implies should exist (Phase 2)."""
    component_id: str
    component_type: str  # database, cache, queue, storage, compute, etc.
    name: str
    evidence: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    aws_services_implied: list[str] = Field(default_factory=list)


class Evidence(BaseModel):
    """Structured evidence for a finding."""
    code: list[str] = Field(default_factory=list)
    runtime: list[str] = Field(default_factory=list)
    infra: list[str] = Field(default_factory=list)
    cost: list[str] = Field(default_factory=list)


class Recommendation(BaseModel):
    """User-facing action item."""
    action_class: ActionClass
    estimated_monthly_savings: float = 0.0
    risk_level: RiskLevel = RiskLevel.low
    rollback: str = ""


class Finding(BaseModel):
    """A drift / waste finding — the core output unit."""
    finding_id: str
    finding_type: FindingType
    resource_type: ResourceType
    resource_id: str
    region: str  # required — must be set explicitly by rule constructors
    title: str
    summary: str
    severity: Severity = Severity.medium
    evidence: Evidence = Field(default_factory=Evidence)
    recommendation: Recommendation
    confidence_score: float = 0.0
    confidence_band: ConfidenceBand = ConfidenceBand.medium
    savings_score: float = 0.0
    actionability_score: float = 0.0
    priority_score: float = 0.0
    metadata: dict = Field(default_factory=dict)
    # metadata holds action-specific data:
    #   old_snapshot: {"snapshot_ids": ["snap-abc", ...], "snapshot_ages": {...}}
    #   orphaned_ebs: {"size_gb": 200, "volume_type": "gp3"}


# ─── API Schemas ───

class DiagnosticRequest(BaseModel):
    """Incoming request to start a diagnostic."""
    role_arn: str = Field(..., pattern=r"^arn:aws:iam::\d{12}:role/.+")
    regions: list[str] = Field(default=["ap-south-1"])
    repo_url: Optional[str] = None  # Phase 2
    repo_branch: str = "main"
    tier: str = "basic"  # basic | deep | sprint


class DiagnosticResponse(BaseModel):
    """Returned to customer."""
    diagnostic_id: str
    account_id: str
    regions: list[str]
    total_resources_scanned: int
    total_findings: int
    total_monthly_savings: float
    total_annual_savings: float
    findings: list[Finding]
    generated_at: datetime = Field(default_factory=datetime.utcnow)


class DiagnosticStatus(BaseModel):
    """Progress polling response."""
    diagnostic_id: str
    status: str  # collecting | analyzing | generating | complete | error
    progress_pct: int = 0
    current_step: str = ""
    findings_so_far: int = 0
