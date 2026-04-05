"""
CloudCut — AWS Inventory Collector
Assumes a cross-account read-only IAM role, inventories resources + usage.
"""
import logging
from datetime import datetime, timedelta
from typing import Optional

import boto3
from botocore.exceptions import ClientError

from cloudcut.models.schemas import AWSResource, ResourceType, ResourceUsage

logger = logging.getLogger(__name__)


class AWSCollector:
    """
    Collects AWS resource inventory and usage metrics.
    Supports two modes:
      - Cross-account: provide role_arn to assume a read-only IAM role via STS
      - Direct: omit role_arn (or pass None) to use local AWS credentials
    Read-only: only uses Describe* / Get* / List* permissions.
    """

    def __init__(self, role_arn: str = None, regions: list[str] = None, external_id: str = ""):
        self.role_arn = role_arn
        self.regions = regions or ["ap-south-1"]
        self.external_id = external_id
        self._sessions: dict[str, boto3.Session] = {}

    def _get_session(self, region: str) -> boto3.Session:
        """Get a boto3 session for the given region.
        Uses STS AssumeRole if role_arn is set, otherwise uses local credentials."""
        if region in self._sessions:
            return self._sessions[region]

        if self.role_arn:
            sts = boto3.client("sts")
            params = {
                "RoleArn": self.role_arn,
                "RoleSessionName": "cloudcut-diagnostic",
                "DurationSeconds": 3600,
            }
            if self.external_id:
                params["ExternalId"] = self.external_id

            creds = sts.assume_role(**params)["Credentials"]
            session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region,
            )
        else:
            session = boto3.Session(region_name=region)

        self._sessions[region] = session
        return session

    def _client(self, service: str, region: str):
        return self._get_session(region).client(service)

    # ─── Resource Collectors ───

    def collect_all(self) -> tuple[list[AWSResource], list[ResourceUsage]]:
        """Run all collectors across all regions."""
        resources: list[AWSResource] = []
        usage: list[ResourceUsage] = []

        collectors = [
            self._collect_ec2,
            self._collect_ebs_volumes,
            self._collect_ebs_snapshots,
            self._collect_eips,
            self._collect_rds,
            self._collect_ecs_services,
            self._collect_lambdas,
            self._collect_nat_gateways,
        ]

        for region in self.regions:
            for collector in collectors:
                try:
                    r, u = collector(region)
                    resources.extend(r)
                    usage.extend(u)
                except ClientError as e:
                    logger.warning(f"{collector.__name__} failed in {region}: {e}")
                except Exception as e:
                    logger.error(f"{collector.__name__} error in {region}: {e}")

        logger.info(f"Collected {len(resources)} resources, {len(usage)} usage records")
        return resources, usage

    def collect_costs(self, days: int = 30) -> dict:
        """Pull Cost Explorer data for the account."""
        try:
            ce = self._client("ce", self.regions[0])
            end = datetime.utcnow().date()
            start = end - timedelta(days=days)
            resp = ce.get_cost_and_usage(
                TimePeriod={"Start": str(start), "End": str(end)},
                Granularity="DAILY",
                Metrics=["BlendedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            )
            return resp
        except ClientError as e:
            logger.error(f"Cost Explorer failed: {e}")
            return {}

    # ─── Individual Collectors ───

    def _collect_ec2(self, region: str) -> tuple[list, list]:
        ec2 = self._client("ec2", region)
        cw = self._client("cloudwatch", region)
        resources, usage = [], []

        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    iid = inst["InstanceId"]
                    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}

                    resources.append(AWSResource(
                        resource_id=iid,
                        resource_type=ResourceType.ec2_instance,
                        region=region,
                        tags=tags,
                        state=inst["State"]["Name"],
                        metadata={
                            "instance_type": inst["InstanceType"],
                            "launch_time": inst.get("LaunchTime", "").isoformat()
                            if inst.get("LaunchTime") else "",
                            "platform": inst.get("Platform", "linux"),
                            "vpc_id": inst.get("VpcId", ""),
                            "subnet_id": inst.get("SubnetId", ""),
                        },
                    ))

                    # Get CPU metrics for running instances
                    if inst["State"]["Name"] == "running":
                        cpu = self._get_metric_avg(
                            cw, "AWS/EC2", "CPUUtilization",
                            [{"Name": "InstanceId", "Value": iid}],
                        )
                        net_in = self._get_metric_sum(
                            cw, "AWS/EC2", "NetworkIn",
                            [{"Name": "InstanceId", "Value": iid}],
                        )
                        net_out = self._get_metric_sum(
                            cw, "AWS/EC2", "NetworkOut",
                            [{"Name": "InstanceId", "Value": iid}],
                        )
                        # Estimate cost from instance type
                        cost_est = self._estimate_ec2_cost(inst["InstanceType"])

                        usage.append(ResourceUsage(
                            resource_id=iid,
                            usage_signals={
                                "cpu_avg": cpu,
                                "network_in_mb": round(net_in / 1e6, 1) if net_in else 0,
                                "network_out_mb": round(net_out / 1e6, 1) if net_out else 0,
                            },
                            cost_signals={"monthly_estimated_usd": cost_est},
                        ))

        return resources, usage

    def _collect_ebs_volumes(self, region: str) -> tuple[list, list]:
        ec2 = self._client("ec2", region)
        resources, usage = [], []

        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for vol in page["Volumes"]:
                tags = {t["Key"]: t["Value"] for t in vol.get("Tags", [])}
                cost = round(vol["Size"] * 0.08, 2)  # ~gp3 pricing
                resources.append(AWSResource(
                    resource_id=vol["VolumeId"],
                    resource_type=ResourceType.ebs_volume,
                    region=region, tags=tags,
                    state=vol["State"],
                    metadata={
                        "size_gb": vol["Size"],
                        "volume_type": vol["VolumeType"],
                        "attachments": [a["InstanceId"] for a in vol.get("Attachments", [])],
                        "create_time": vol.get("CreateTime", "").isoformat()
                        if vol.get("CreateTime") else "",
                    },
                ))
                usage.append(ResourceUsage(
                    resource_id=vol["VolumeId"],
                    cost_signals={"monthly_estimated_usd": cost},
                ))
        return resources, usage

    def _collect_ebs_snapshots(self, region: str) -> tuple[list, list]:
        ec2 = self._client("ec2", region)
        sts = self._client("sts", region)
        account_id = sts.get_caller_identity()["Account"]
        resources = []

        paginator = ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=[account_id]):
            for snap in page["Snapshots"]:
                tags = {t["Key"]: t["Value"] for t in snap.get("Tags", [])}
                cost = round(snap["VolumeSize"] * 0.05 / 30, 2)  # rough monthly
                resources.append(AWSResource(
                    resource_id=snap["SnapshotId"],
                    resource_type=ResourceType.ebs_snapshot,
                    region=region, tags=tags,
                    state=snap["State"],
                    metadata={
                        "volume_size_gb": snap["VolumeSize"],
                        "start_time": snap.get("StartTime", "").isoformat()
                        if snap.get("StartTime") else "",
                        "volume_id": snap.get("VolumeId", ""),
                    },
                ))
        return resources, []

    def _collect_eips(self, region: str) -> tuple[list, list]:
        ec2 = self._client("ec2", region)
        resources = []
        resp = ec2.describe_addresses()
        for addr in resp.get("Addresses", []):
            resources.append(AWSResource(
                resource_id=addr.get("AllocationId", addr.get("PublicIp", "")),
                resource_type=ResourceType.elastic_ip,
                region=region,
                tags={t["Key"]: t["Value"] for t in addr.get("Tags", [])},
                state="associated" if addr.get("AssociationId") else "unassociated",
                metadata={
                    "public_ip": addr.get("PublicIp", ""),
                    "association_id": addr.get("AssociationId"),
                    "instance_id": addr.get("InstanceId"),
                },
            ))
        return resources, []

    def _collect_rds(self, region: str) -> tuple[list, list]:
        rds = self._client("rds", region)
        cw = self._client("cloudwatch", region)
        resources, usage = [], []

        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                dbid = db["DBInstanceIdentifier"]
                resources.append(AWSResource(
                    resource_id=dbid,
                    resource_type=ResourceType.rds_instance,
                    region=region,
                    tags={},  # RDS tags need separate API call
                    state=db["DBInstanceStatus"],
                    metadata={
                        "instance_class": db["DBInstanceClass"],
                        "engine": db["Engine"],
                        "engine_version": db.get("EngineVersion", ""),
                        "multi_az": db.get("MultiAZ", False),
                        "allocated_storage_gb": db.get("AllocatedStorage", 0),
                        "storage_type": db.get("StorageType", ""),
                    },
                ))
                cpu = self._get_metric_avg(
                    cw, "AWS/RDS", "CPUUtilization",
                    [{"Name": "DBInstanceIdentifier", "Value": dbid}],
                )
                conns = self._get_metric_avg(
                    cw, "AWS/RDS", "DatabaseConnections",
                    [{"Name": "DBInstanceIdentifier", "Value": dbid}],
                )
                cost = self._estimate_rds_cost(db["DBInstanceClass"], db.get("MultiAZ", False))
                usage.append(ResourceUsage(
                    resource_id=dbid,
                    usage_signals={"cpu_avg": cpu, "connections_avg": conns},
                    cost_signals={"monthly_estimated_usd": cost},
                ))
        return resources, usage

    def _collect_ecs_services(self, region: str) -> tuple[list, list]:
        ecs = self._client("ecs", region)
        resources, usage = [], []

        clusters = ecs.list_clusters().get("clusterArns", [])
        for cluster_arn in clusters:
            svcs = ecs.list_services(cluster=cluster_arn).get("serviceArns", [])
            if not svcs:
                continue
            details = ecs.describe_services(cluster=cluster_arn, services=svcs[:10])
            for svc in details.get("services", []):
                resources.append(AWSResource(
                    resource_id=svc["serviceName"],
                    resource_type=ResourceType.ecs_service,
                    region=region, tags={},
                    state=svc["status"],
                    metadata={
                        "cluster": cluster_arn.split("/")[-1],
                        "desired_count": svc["desiredCount"],
                        "running_count": svc["runningCount"],
                        "launch_type": svc.get("launchType", "FARGATE"),
                    },
                ))
        return resources, usage

    def _collect_lambdas(self, region: str) -> tuple[list, list]:
        lam = self._client("lambda", region)
        cw = self._client("cloudwatch", region)
        resources, usage = [], []

        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page["Functions"]:
                fname = fn["FunctionName"]
                resources.append(AWSResource(
                    resource_id=fname,
                    resource_type=ResourceType.lambda_function,
                    region=region, tags={},
                    state="active",
                    metadata={
                        "runtime": fn.get("Runtime", ""),
                        "memory_mb": fn.get("MemorySize", 128),
                        "timeout": fn.get("Timeout", 3),
                        "last_modified": fn.get("LastModified", ""),
                    },
                ))
                invocations = self._get_metric_sum(
                    cw, "AWS/Lambda", "Invocations",
                    [{"Name": "FunctionName", "Value": fname}],
                )
                usage.append(ResourceUsage(
                    resource_id=fname,
                    usage_signals={"invocations": invocations or 0},
                    cost_signals={},
                ))
        return resources, usage

    def _collect_nat_gateways(self, region: str) -> tuple[list, list]:
        ec2 = self._client("ec2", region)
        cw = self._client("cloudwatch", region)
        resources, usage = [], []

        resp = ec2.describe_nat_gateways(
            Filter=[{"Name": "state", "Values": ["available"]}]
        )
        for nat in resp.get("NatGateways", []):
            natid = nat["NatGatewayId"]
            resources.append(AWSResource(
                resource_id=natid,
                resource_type=ResourceType.nat_gateway,
                region=region, tags={},
                state=nat["State"],
                metadata={
                    "subnet_id": nat.get("SubnetId", ""),
                    "vpc_id": nat.get("VpcId", ""),
                },
            ))
            bytes_out = self._get_metric_sum(
                cw, "AWS/NATGateway", "BytesOutToDestination",
                [{"Name": "NatGatewayId", "Value": natid}],
            )
            cost_fixed = 32.40  # $0.045/hr
            cost_data = round((bytes_out or 0) / 1e9 * 0.045, 2)
            usage.append(ResourceUsage(
                resource_id=natid,
                usage_signals={"bytes_out": bytes_out or 0},
                cost_signals={"monthly_estimated_usd": cost_fixed + cost_data},
            ))
        return resources, usage

    # ─── Helpers ───

    def _get_metric_avg(self, cw, namespace, metric, dimensions, days=30) -> Optional[float]:
        try:
            resp = cw.get_metric_statistics(
                Namespace=namespace, MetricName=metric,
                Dimensions=dimensions,
                StartTime=datetime.utcnow() - timedelta(days=days),
                EndTime=datetime.utcnow(),
                Period=86400 * days,
                Statistics=["Average"],
            )
            points = resp.get("Datapoints", [])
            return round(points[0]["Average"], 2) if points else None
        except Exception:
            return None

    def _get_metric_sum(self, cw, namespace, metric, dimensions, days=30) -> Optional[float]:
        try:
            resp = cw.get_metric_statistics(
                Namespace=namespace, MetricName=metric,
                Dimensions=dimensions,
                StartTime=datetime.utcnow() - timedelta(days=days),
                EndTime=datetime.utcnow(),
                Period=86400 * days,
                Statistics=["Sum"],
            )
            points = resp.get("Datapoints", [])
            return round(points[0]["Sum"], 2) if points else None
        except Exception:
            return None

    # Rough cost estimates (replace with pricing API in production)
    _EC2_HOURLY = {
        "t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416,
        "t3.large": 0.0832, "m5.large": 0.096, "m5.xlarge": 0.192,
        "r5.large": 0.126, "r5.xlarge": 0.252,
        "g4dn.xlarge": 0.526, "g4dn.2xlarge": 0.752,
        "p3.2xlarge": 3.06,
    }

    def _estimate_ec2_cost(self, instance_type: str) -> float:
        hourly = self._EC2_HOURLY.get(instance_type, 0.10)
        return round(hourly * 730, 2)

    _RDS_HOURLY = {
        "db.t3.micro": 0.017, "db.t3.small": 0.034, "db.t3.medium": 0.068,
        "db.r5.large": 0.24, "db.r5.xlarge": 0.48,
        "db.r6g.large": 0.26,
    }

    def _estimate_rds_cost(self, instance_class: str, multi_az: bool) -> float:
        hourly = self._RDS_HOURLY.get(instance_class, 0.10)
        monthly = hourly * 730
        if multi_az:
            monthly *= 2
        return round(monthly, 2)
