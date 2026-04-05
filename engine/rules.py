"""
CloudCut — Rules Engine
10 deterministic checks. Rules first, LLM for explanation only.
"""
import logging
import uuid
from datetime import datetime, timedelta

from cloudcut.models.schemas import (
    AWSResource, ResourceUsage, Finding, FindingType, ResourceType,
    ActionClass, RiskLevel, Severity, Evidence, Recommendation,
    ConfidenceBand,
)

logger = logging.getLogger(__name__)


def classify_confidence(score: float) -> ConfidenceBand:
    if score >= 0.85:
        return ConfidenceBand.high
    elif score >= 0.65:
        return ConfidenceBand.medium
    elif score >= 0.45:
        return ConfidenceBand.low
    return ConfidenceBand.informational


def compute_savings_score(
    cost_magnitude: float,     # 1-10
    waste_likelihood: float,   # 1-10
    recurring: float,          # 1-10
    optimization_depth: float, # 1-10
) -> float:
    return round(
        0.50 * cost_magnitude +
        0.20 * waste_likelihood +
        0.20 * recurring +
        0.10 * optimization_depth,
        2,
    )


def compute_actionability_score(
    reversibility: float,      # 1-10
    confidence: float,         # 1-10
    dependency_clarity: float, # 1-10
    operational_ease: float,   # 1-10
) -> float:
    return round(
        0.35 * reversibility +
        0.25 * confidence +
        0.20 * dependency_clarity +
        0.20 * operational_ease,
        2,
    )


def compute_priority(savings_score: float, actionability_score: float) -> float:
    return round(0.6 * savings_score + 0.4 * actionability_score, 2)


def _fid() -> str:
    return f"f_{uuid.uuid4().hex[:8]}"


# ─── The 10 Checks ───

def check_orphaned_ebs(
    resources: list[AWSResource],
    usage: list[ResourceUsage],
) -> list[Finding]:
    """Check 1: Unattached EBS volumes."""
    findings = []
    for r in resources:
        if r.resource_type != ResourceType.ebs_volume:
            continue
        if r.state != "available":
            continue
        attachments = r.metadata.get("attachments", [])
        if attachments:
            continue

        size = r.metadata.get("size_gb", 0)
        cost = round(size * 0.08, 2)  # gp3 est.

        ss = compute_savings_score(
            cost_magnitude=min(10, cost / 5),
            waste_likelihood=9.5,
            recurring=9,
            optimization_depth=10,
        )
        aa = compute_actionability_score(
            reversibility=6,    # can recreate from snapshot
            confidence=9.5,
            dependency_clarity=9,
            operational_ease=10,
        )

        findings.append(Finding(
            finding_id=_fid(),
            finding_type=FindingType.orphaned_ebs,
            resource_type=ResourceType.ebs_volume,
            resource_id=r.resource_id,
            region=r.region,
            title=f"Unattached EBS volume ({size}GB)",
            summary=f"EBS volume {r.resource_id} has no attached instance. "
                    f"Likely orphaned from a terminated instance or old deployment.",
            severity=Severity.high if cost > 5 else Severity.medium,
            evidence=Evidence(
                infra=[f"Volume status: available (no attachments)"],
                cost=[f"Estimated cost: ${cost}/mo ({size}GB {r.metadata.get('volume_type', 'gp3')})"],
            ),
            recommendation=Recommendation(
                action_class=ActionClass.terminate,
                estimated_monthly_savings=cost,
                risk_level=RiskLevel.low,
                rollback="Create volume from snapshot if data is needed",
            ),
            confidence_score=0.95,
            confidence_band=ConfidenceBand.high,
            savings_score=ss,
            actionability_score=aa,
            priority_score=compute_priority(ss, aa),
        ))
    return findings


def check_unassociated_eips(
    resources: list[AWSResource],
    usage: list[ResourceUsage],
) -> list[Finding]:
    """Check 2: Elastic IPs not attached to anything."""
    findings = []
    for r in resources:
        if r.resource_type != ResourceType.elastic_ip:
            continue
        if r.state == "associated":
            continue

        findings.append(Finding(
            finding_id=_fid(),
            finding_type=FindingType.unassociated_eip,
            resource_type=ResourceType.elastic_ip,
            resource_id=r.resource_id,
            region=r.region,
            title=f"Unassociated Elastic IP ({r.metadata.get('public_ip', '')})",
            summary=f"Elastic IP is not attached to any instance or ENI. "
                    f"Billed at $3.60/mo since Feb 2024 pricing change.",
            severity=Severity.medium,
            evidence=Evidence(
                infra=["No association ID — EIP is idle"],
                cost=["$3.60/mo (AWS charges for unattached EIPs since Feb 2024)"],
            ),
            recommendation=Recommendation(
                action_class=ActionClass.terminate,
                estimated_monthly_savings=3.60,
                risk_level=RiskLevel.low,
                rollback="Allocate a new EIP if needed later",
            ),
            confidence_score=0.95,
            confidence_band=ConfidenceBand.high,
            savings_score=compute_savings_score(2, 10, 9, 10),
            actionability_score=compute_actionability_score(8, 10, 10, 10),
            priority_score=0,
        ))
        findings[-1].priority_score = compute_priority(
            findings[-1].savings_score, findings[-1].actionability_score
        )
    return findings


def check_old_snapshots(
    resources: list[AWSResource],
    usage: list[ResourceUsage],
    max_age_days: int = 30,
) -> list[Finding]:
    """Check 3: Snapshots beyond retention threshold. Emits exact snapshot IDs."""
    findings = []
    now = datetime.utcnow()
    old_snaps = []

    for r in resources:
        if r.resource_type != ResourceType.ebs_snapshot:
            continue
        start_str = r.metadata.get("start_time", "")
        if not start_str:
            continue
        try:
            start = datetime.fromisoformat(start_str.replace("Z", "+00:00")).replace(tzinfo=None)
        except (ValueError, TypeError):
            continue
        age = (now - start).days
        if age > max_age_days:
            old_snaps.append((r, age))

    if not old_snaps:
        return findings

    total_gb = sum(r.metadata.get("volume_size_gb", 0) for r, _ in old_snaps)
    total_cost = round(total_gb * 0.05, 2)
    region = old_snaps[0][0].region if old_snaps else "ap-south-1"

    # Collect exact snapshot IDs for targeted deletion
    snap_ids = [r.resource_id for r, _ in old_snaps]
    snap_details = {r.resource_id: age for r, age in old_snaps}

    findings.append(Finding(
        finding_id=_fid(),
        finding_type=FindingType.old_snapshot,
        resource_type=ResourceType.ebs_snapshot,
        resource_id=f"{len(old_snaps)}_snapshots",
        region=region,
        title=f"{len(old_snaps)} snapshots older than {max_age_days} days",
        summary=f"Found {len(old_snaps)} snapshots totaling {total_gb}GB. "
                f"Oldest is {max(age for _, age in old_snaps)} days old. "
                f"IDs: {', '.join(snap_ids[:5])}{'...' if len(snap_ids) > 5 else ''}",
        severity=Severity.medium,
        evidence=Evidence(
            infra=[
                f"{len(old_snaps)} snapshots exceed {max_age_days}-day threshold",
                f"Snapshot IDs: {', '.join(snap_ids)}",
            ],
            cost=[f"Estimated total cost: ${total_cost}/mo ({total_gb}GB)"],
        ),
        recommendation=Recommendation(
            action_class=ActionClass.terminate,
            estimated_monthly_savings=total_cost,
            risk_level=RiskLevel.low,
            rollback="Snapshots cannot be recovered once deleted",
        ),
        confidence_score=0.82,
        confidence_band=ConfidenceBand.medium,
        savings_score=compute_savings_score(min(10, total_cost / 3), 7, 9, 10),
        actionability_score=compute_actionability_score(3, 8, 8, 9),
        priority_score=0,
        metadata={
            "snapshot_ids": snap_ids,
            "snapshot_ages": snap_details,
            "total_gb": total_gb,
        },
    ))
    findings[-1].priority_score = compute_priority(
        findings[-1].savings_score, findings[-1].actionability_score
    )
    return findings


def check_idle_ec2(
    resources: list[AWSResource],
    usage: list[ResourceUsage],
    cpu_threshold: float = 5.0,
) -> list[Finding]:
    """Check 4: EC2 running 24/7 with low utilization."""
    findings = []
    usage_map = {u.resource_id: u for u in usage}

    for r in resources:
        if r.resource_type != ResourceType.ec2_instance:
            continue
        if r.state != "running":
            continue

        u = usage_map.get(r.resource_id)
        if not u:
            continue
        cpu = u.usage_signals.get("cpu_avg")
        if cpu is None or cpu > cpu_threshold:
            continue

        cost = u.cost_signals.get("monthly_estimated_usd", 0)
        savings = round(cost * 0.5, 2)  # schedule = 50% savings estimate
        itype = r.metadata.get("instance_type", "unknown")

        findings.append(Finding(
            finding_id=_fid(),
            finding_type=FindingType.idle_ec2,
            resource_type=ResourceType.ec2_instance,
            resource_id=r.resource_id,
            region=r.region,
            title=f"Idle EC2 instance ({itype})",
            summary=f"Instance {r.resource_id} ({itype}) has avg CPU {cpu}% over 30 days. "
                    f"Running 24/7 at ${cost}/mo with minimal utilization.",
            severity=Severity.high if cost > 100 else Severity.medium,
            evidence=Evidence(
                runtime=[
                    f"Average CPU: {cpu}% (threshold: {cpu_threshold}%)",
                    f"Network in: {u.usage_signals.get('network_in_mb', 0)}MB/30d",
                ],
                cost=[f"Monthly cost: ${cost}"],
            ),
            recommendation=Recommendation(
                action_class=ActionClass.stop_schedule,
                estimated_monthly_savings=savings,
                risk_level=RiskLevel.low,
                rollback="Restart instance manually or disable schedule",
            ),
            confidence_score=0.85 if cpu < 3 else 0.72,
            confidence_band=classify_confidence(0.85 if cpu < 3 else 0.72),
            savings_score=compute_savings_score(min(10, cost / 30), 8, 9, 7),
            actionability_score=compute_actionability_score(9, 8, 6, 8),
            priority_score=0,
        ))
        findings[-1].priority_score = compute_priority(
            findings[-1].savings_score, findings[-1].actionability_score
        )
    return findings


def check_gpu_non_prod(
    resources: list[AWSResource],
    usage: list[ResourceUsage],
) -> list[Finding]:
    """Check 5: GPU instances in dev/staging or untagged."""
    findings = []
    usage_map = {u.resource_id: u for u in usage}
    gpu_prefixes = ("g4dn", "g5", "p3", "p4", "p5", "g6", "gr6")

    for r in resources:
        if r.resource_type != ResourceType.ec2_instance:
            continue
        if r.state != "running":
            continue
        itype = r.metadata.get("instance_type", "")
        if not any(itype.startswith(p) for p in gpu_prefixes):
            continue

        env_tag = r.tags.get("Environment", r.tags.get("env", "")).lower()
        is_prod = env_tag in ("production", "prod")
        if is_prod:
            continue

        u = usage_map.get(r.resource_id)
        cost = u.cost_signals.get("monthly_estimated_usd", 0) if u else 0
        cpu = u.usage_signals.get("cpu_avg", 0) if u else 0

        findings.append(Finding(
            finding_id=_fid(),
            finding_type=FindingType.gpu_non_prod,
            resource_type=ResourceType.ec2_instance,
            resource_id=r.resource_id,
            region=r.region,
            title=f"GPU instance ({itype}) in non-production",
            summary=f"GPU instance {r.resource_id} ({itype}) appears to be non-production "
                    f"(env tag: '{env_tag or 'untagged'}'). Running at ${cost}/mo.",
            severity=Severity.critical,
            evidence=Evidence(
                runtime=[f"CPU avg: {cpu}%"] if cpu else [],
                infra=[f"Environment tag: '{env_tag or 'not set'}'"],
                cost=[f"Monthly cost: ${cost} ({itype})"],
            ),
            recommendation=Recommendation(
                action_class=ActionClass.stop_schedule,
                estimated_monthly_savings=round(cost * 0.5, 2),
                risk_level=RiskLevel.low,
                rollback="Start instance when needed",
            ),
            confidence_score=0.90 if not env_tag else 0.78,
            confidence_band=classify_confidence(0.90 if not env_tag else 0.78),
            savings_score=compute_savings_score(min(10, cost / 30), 9, 9, 8),
            actionability_score=compute_actionability_score(9, 9, 7, 8),
            priority_score=0,
        ))
        findings[-1].priority_score = compute_priority(
            findings[-1].savings_score, findings[-1].actionability_score
        )
    return findings


def check_zero_invocation_lambda(
    resources: list[AWSResource],
    usage: list[ResourceUsage],
) -> list[Finding]:
    """Check 6: Lambda functions with zero invocations in 30 days."""
    findings = []
    usage_map = {u.resource_id: u for u in usage}

    for r in resources:
        if r.resource_type != ResourceType.lambda_function:
            continue
        u = usage_map.get(r.resource_id)
        if not u:
            continue
        invocations = u.usage_signals.get("invocations", -1)
        if invocations != 0:
            continue

        findings.append(Finding(
            finding_id=_fid(),
            finding_type=FindingType.zero_invocation_lambda,
            resource_type=ResourceType.lambda_function,
            resource_id=r.resource_id,
            region=r.region,
            title=f"Lambda '{r.resource_id}' — zero invocations (30d)",
            summary=f"Function has not been invoked in the last 30 days. "
                    f"Likely stale or replaced by another implementation.",
            severity=Severity.medium,
            evidence=Evidence(
                runtime=["0 invocations in 30-day window"],
                infra=[f"Runtime: {r.metadata.get('runtime', 'unknown')}"],
            ),
            recommendation=Recommendation(
                action_class=ActionClass.review_architecture,
                estimated_monthly_savings=0,  # Lambda doesn't cost at zero invocations
                risk_level=RiskLevel.low,
                rollback="Re-deploy function if needed",
            ),
            confidence_score=0.80,
            confidence_band=ConfidenceBand.medium,
            savings_score=compute_savings_score(1, 8, 5, 5),
            actionability_score=compute_actionability_score(9, 8, 6, 9),
            priority_score=0,
        ))
        findings[-1].priority_score = compute_priority(
            findings[-1].savings_score, findings[-1].actionability_score
        )
    return findings


def check_idle_ecs(
    resources: list[AWSResource],
    usage: list[ResourceUsage],
) -> list[Finding]:
    """Check 7: ECS/Fargate services running with desired > 0 but no traffic."""
    findings = []
    for r in resources:
        if r.resource_type != ResourceType.ecs_service:
            continue
        desired = r.metadata.get("desired_count", 0)
        running = r.metadata.get("running_count", 0)
        if desired == 0 and running == 0:
            continue  # already scaled to zero

        # Flag if running but we can't verify traffic (needs ALB metrics)
        if running > 0:
            findings.append(Finding(
                finding_id=_fid(),
                finding_type=FindingType.idle_ecs,
                resource_type=ResourceType.ecs_service,
                resource_id=r.resource_id,
                region=r.region,
                title=f"ECS service '{r.resource_id}' — review utilization",
                summary=f"Service running {running} tasks (desired: {desired}) in "
                        f"cluster '{r.metadata.get('cluster', '')}'. "
                        f"Verify traffic justifies running count.",
                severity=Severity.medium,
                evidence=Evidence(
                    infra=[
                        f"Desired count: {desired}, Running: {running}",
                        f"Launch type: {r.metadata.get('launch_type', 'FARGATE')}",
                    ],
                ),
                recommendation=Recommendation(
                    action_class=ActionClass.rightsize,
                    estimated_monthly_savings=0,  # needs ALB data
                    risk_level=RiskLevel.medium,
                    rollback="Increase desired count",
                ),
                confidence_score=0.55,
                confidence_band=ConfidenceBand.low,
                savings_score=compute_savings_score(5, 5, 8, 5),
                actionability_score=compute_actionability_score(8, 5, 5, 7),
                priority_score=0,
            ))
            findings[-1].priority_score = compute_priority(
                findings[-1].savings_score, findings[-1].actionability_score
            )
    return findings


def check_oversized_rds(
    resources: list[AWSResource],
    usage: list[ResourceUsage],
    cpu_threshold: float = 15.0,
) -> list[Finding]:
    """Check 8: RDS oversized relative to utilization."""
    findings = []
    usage_map = {u.resource_id: u for u in usage}

    for r in resources:
        if r.resource_type != ResourceType.rds_instance:
            continue
        u = usage_map.get(r.resource_id)
        if not u:
            continue
        cpu = u.usage_signals.get("cpu_avg")
        if cpu is None or cpu > cpu_threshold:
            continue

        cost = u.cost_signals.get("monthly_estimated_usd", 0)
        iclass = r.metadata.get("instance_class", "unknown")
        multi_az = r.metadata.get("multi_az", False)
        savings_notes = []
        savings = 0

        if multi_az:
            savings += round(cost * 0.5, 2)
            savings_notes.append("Disable Multi-AZ (halves cost)")
        if cpu < 10:
            savings += round(cost * 0.25, 2)
            savings_notes.append("Downsize instance class")

        findings.append(Finding(
            finding_id=_fid(),
            finding_type=FindingType.oversized_rds,
            resource_type=ResourceType.rds_instance,
            resource_id=r.resource_id,
            region=r.region,
            title=f"Oversized RDS ({iclass}{'+ Multi-AZ' if multi_az else ''})",
            summary=f"RDS instance '{r.resource_id}' ({iclass}) has avg CPU {cpu}%. "
                    f"{'Multi-AZ enabled. ' if multi_az else ''}"
                    f"Current cost: ${cost}/mo.",
            severity=Severity.high if cost > 150 else Severity.medium,
            evidence=Evidence(
                runtime=[
                    f"Average CPU: {cpu}%",
                    f"Avg connections: {u.usage_signals.get('connections_avg', 'N/A')}",
                ],
                infra=[
                    f"Instance class: {iclass}",
                    f"Multi-AZ: {multi_az}",
                    f"Storage: {r.metadata.get('allocated_storage_gb', '?')}GB "
                    f"({r.metadata.get('storage_type', '')})",
                ],
                cost=[f"Monthly cost: ${cost}"],
            ),
            recommendation=Recommendation(
                action_class=ActionClass.rightsize,
                estimated_monthly_savings=savings,
                risk_level=RiskLevel.medium,
                rollback="Upgrade instance class or re-enable Multi-AZ",
            ),
            confidence_score=0.78 if cpu < 10 else 0.65,
            confidence_band=classify_confidence(0.78 if cpu < 10 else 0.65),
            savings_score=compute_savings_score(min(10, cost / 20), 7, 9, 6),
            actionability_score=compute_actionability_score(7, 7, 6, 5),
            priority_score=0,
        ))
        findings[-1].priority_score = compute_priority(
            findings[-1].savings_score, findings[-1].actionability_score
        )
    return findings


def check_nat_gateway_anomaly(
    resources: list[AWSResource],
    usage: list[ResourceUsage],
) -> list[Finding]:
    """Check 10: NAT Gateway with high data processing charges."""
    findings = []
    usage_map = {u.resource_id: u for u in usage}

    for r in resources:
        if r.resource_type != ResourceType.nat_gateway:
            continue
        u = usage_map.get(r.resource_id)
        if not u:
            continue

        cost = u.cost_signals.get("monthly_estimated_usd", 0)
        bytes_out = u.usage_signals.get("bytes_out", 0)
        gb_out = round(bytes_out / 1e9, 1) if bytes_out else 0

        findings.append(Finding(
            finding_id=_fid(),
            finding_type=FindingType.nat_gateway_anomaly,
            resource_type=ResourceType.nat_gateway,
            resource_id=r.resource_id,
            region=r.region,
            title=f"NAT Gateway — review data processing cost",
            summary=f"NAT Gateway {r.resource_id} costs ${cost}/mo "
                    f"({gb_out}GB processed). Consider VPC endpoints for S3/ECR/CloudWatch.",
            severity=Severity.medium if cost < 60 else Severity.high,
            evidence=Evidence(
                infra=[f"Subnet: {r.metadata.get('subnet_id', '')}"],
                cost=[
                    f"Fixed cost: $32.40/mo",
                    f"Data processing: ~${round(cost - 32.40, 2)}/mo ({gb_out}GB)",
                ],
            ),
            recommendation=Recommendation(
                action_class=ActionClass.review_architecture,
                estimated_monthly_savings=round(max(0, cost - 32.40) * 0.6, 2),
                risk_level=RiskLevel.low,
                rollback="Remove VPC endpoints to revert",
            ),
            confidence_score=0.70,
            confidence_band=ConfidenceBand.medium,
            savings_score=compute_savings_score(min(10, cost / 10), 6, 9, 5),
            actionability_score=compute_actionability_score(9, 7, 6, 5),
            priority_score=0,
        ))
        findings[-1].priority_score = compute_priority(
            findings[-1].savings_score, findings[-1].actionability_score
        )
    return findings


# ─── Runner ───

ALL_CHECKS = [
    check_orphaned_ebs,
    check_unassociated_eips,
    check_old_snapshots,
    check_idle_ec2,
    check_gpu_non_prod,
    check_zero_invocation_lambda,
    check_idle_ecs,
    check_oversized_rds,
    # check 9 (code/infra drift) requires code parser — Phase 2
    check_nat_gateway_anomaly,
]


def run_all_checks(
    resources: list[AWSResource],
    usage: list[ResourceUsage],
) -> list[Finding]:
    """Execute all checks and return priority-sorted findings."""
    findings: list[Finding] = []
    for check_fn in ALL_CHECKS:
        try:
            results = check_fn(resources, usage)
            findings.extend(results)
            logger.info(f"{check_fn.__name__}: {len(results)} findings")
        except Exception as e:
            logger.error(f"{check_fn.__name__} failed: {e}")

    findings.sort(key=lambda f: f.priority_score, reverse=True)
    return findings
