# CloudCut

Scan your AWS account for waste and fix low-risk issues with approval.

I cut my own AWS bill from $265/mo to $116/mo in one terminal session. CloudCut automates the exact process I used.

**[🌐 Website](https://cloudcut-landing.vercel.app)** · **[▶️ Demo Video](https://youtu.be/YOUR_VIDEO_ID)** · **[💰 Get Full Report ($19)](https://rzp.io/rzp/KhtM412)**

---

## What it does

CloudCut runs 5 deterministic checks against your AWS account: orphaned EBS volumes, unused Elastic IPs, old snapshots, idle EC2 instances, and oversized RDS. No LLM guessing — pure arithmetic. It finds waste, shows you exactly what to fix, and safely deletes the obvious stuff with your approval. Your credentials never leave your machine.

## Install

```bash
git clone https://github.com/rssubramaniyan1/cloudcut.git
cd cloudcut
pip install mcp pydantic boto3 python-dotenv
```

Make sure your AWS CLI is configured:

```bash
aws sts get-caller-identity
```

## Use with Claude Code

Drop the `.mcp.json` into your project root. Open Claude Code and say:

```
Scan my AWS account for waste.
```

Claude Code calls CloudCut's tools automatically: inventory → cost analysis → waste checks → report.

## Use standalone

```bash
python3 -c "
from cloudcut.collectors.aws_inventory import AWSCollector
from cloudcut.engine.rules import run_all_checks

collector = AWSCollector(role_arn=None, regions=['ap-south-1'])
resources, usage = collector.collect_all()
findings = run_all_checks(resources, usage)

for f in findings:
    print(f'{f.title} — \${f.recommendation.estimated_monthly_savings}/mo')
"
```

## Free vs Paid

| | Free | Full Report ($19) |
|---|---|---|
| Findings shown | Top 3 | All |
| Safe auto-fix | Top 3 | All |
| CLI commands | All findings | All findings |
| Total savings shown | Yes | Yes |
| Downloadable report | No | Yes |

After payment, set your license key:

```bash
export CLOUDCUT_LICENSE_KEY=CC-XXXX-XXXX-XXXX
```

## What can be auto-fixed

Only 3 low-risk resource types. Everything else gets a CLI command you run yourself.

- ✅ Orphaned EBS volumes (unattached storage)
- ✅ Unassociated Elastic IPs ($3.60/mo each)
- ✅ Old EBS snapshots (targeted by specific ID)
- ❌ EC2 instances — report only
- ❌ RDS instances — report only
- ❌ ECS services — report only
- ❌ NAT Gateways — report only

## Trust model

- Rules are deterministic, not LLM-driven
- Every fix requires explicit `--confirm`
- Dry-run shows exact before/after state before any action
- Every action logged to `~/.cloudcut/action_log.jsonl`
- Credentials never leave your machine

## Proof

| Resource | Action | Saved |
|---|---|---|
| 200GB orphaned EBS (10 months!) | Deleted | $18/mo |
| 800GB EBS on stopped GPU instances | Snapshot → Delete | $73/mo |
| Unused Elastic IP | Released | $4/mo |
| NAT Gateway (zero traffic) | Deleted | $22/mo |
| RegAssure ALB + WAF (guarding nothing) | Deleted | $11/mo |
| regassure-db (missed during manual cleanup) | Terminated | $12/mo |
| **Total** | | **$137/mo · $1,644/yr** |

## Links

- 🌐 Landing page: [cloudcut-landing.vercel.app](https://cloudcut-landing.vercel.app)
- ▶️ Demo video: [youtube.com/watch?v=YOUR_VIDEO_ID](https://youtu.be/YOUR_VIDEO_ID)
- 🔧 MCP server (remote): [cloudcut-sn1p.onrender.com](https://cloudcut-sn1p.onrender.com)
- 💰 Full report: [$19 via Razorpay](https://rzp.io/rzp/KhtM412)

## License

MIT
