# CloudCut

Scan your AWS account for waste and fix low-risk issues with approval. CloudCut runs as a local MCP server inside Claude Code — it collects your AWS inventory, runs deterministic cost checks, shows you exactly what's wasting money, and safely deletes orphaned resources (EBS volumes, unassociated Elastic IPs, old snapshots) after you confirm each action. The founder cut his own AWS bill from $265/mo to $128/mo in one terminal session.

## Install

1. Install dependencies:

```bash
pip install mcp pydantic boto3 anthropic python-dotenv
```

2. Copy `.mcp.json` into your Claude Code project root (already included in this repo).

3. Configure AWS credentials. CloudCut uses your local AWS profile:

```bash
export AWS_PROFILE=your-profile
export AWS_REGION=ap-south-1   # or your primary region
```

The MCP server needs read access to EC2, EBS, EIP, RDS, ECS, Cost Explorer, and CloudWatch. For cross-account scanning, deploy the IAM role template in `infra/readonly-role.yaml`.

## Free tier

- **Top 3 findings** ranked by savings, with full details
- **Safe-fix** for those 3 findings (orphaned EBS, unassociated EIP, old snapshots only)
- **CLI commands** shown for all findings, including ones you can't auto-fix
- **Total savings** across all findings shown, so you know what you're leaving on the table

## Paid tier — $19 one-time

- **All findings** unlocked (no cap)
- **All safe-fixes** executable
- **Downloadable HTML report** with full breakdown

Get the full report at [cloudcut.dev/report](https://cloudcut.dev/report).
