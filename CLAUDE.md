# CLAUDE.md — CloudCut Project Handoff

## What this project is

CloudCut is an AWS cost diagnostic tool that scans an AWS account for waste and lets users fix low-risk issues with approval. It runs as a local MCP server for Claude Code and will also have a $19 paid report via a web landing page.

**One-line positioning:** "Scan your AWS account for waste and fix low-risk issues with approval."

**Proof point:** The founder (Ravi) cut his own AWS bill from $265/mo to $128/mo in one terminal session using the exact checks this tool automates.

## Current state

The core analyzer is built and code-complete. All Python files compile clean. What exists:

```
cloudcut/
├── cloudcut_mcp_server.py    # MCP server with 9 tools (4 diagnostic, 3 remediation/verify, 2 Phase 2 stubs)
├── .mcp.json                 # Claude Code MCP config
├── demo.py                   # Interactive terminal demo with real account data
├── requirements.txt          # fastapi, uvicorn, pydantic, boto3, anthropic, python-dotenv
├── collectors/
│   └── aws_inventory.py      # AWS resource collector via cross-account IAM role (boto3)
├── engine/
│   ├── rules.py              # 9 deterministic waste checks (5 high-confidence for launch)
│   ├── allowlist.py          # SAFE_FIX_ALLOWLIST: only orphaned_ebs, unassociated_eip, old_snapshot
│   ├── action_log.py         # Append-only JSONL log at ~/.cloudcut/action_log.jsonl
│   └── tier_gate.py          # Free (top 3) vs paid ($19, all findings) boundary
├── models/
│   └── schemas.py            # Pydantic v2 models: AWSResource, Finding, Recommendation, etc.
├── api/
│   └── main.py               # FastAPI endpoints (for future web product, not needed for MCP launch)
├── infra/
│   └── readonly-role.yaml    # CloudFormation template for customer's read-only IAM role
├── parsers/                  # Empty — Phase 2 code parser goes here
└── reports/                  # Empty — HTML/PDF report generator goes here
```

## What has NOT been done yet

These are the launch tasks, in priority order:

### Priority 1: Clean the package
- Delete any `__pycache__/` directories and `.pyc` files
- Remove the accidental `cloudcut/{api,collectors,engine,parsers,models,reports,tests}/` directory (shell brace expansion artifact)
- Verify all files compile: `python -m py_compile cloudcut/cloudcut_mcp_server.py` etc.

### Priority 2: Write README.md
Four sections only:
1. **What it does** — one paragraph. AWS cost scanner, finds waste, fixes safe issues with approval.
2. **Install** — pip install deps, copy `.mcp.json`, configure AWS credentials.
3. **Free tier** — top 3 findings, safe-fix for those 3, CLI commands for all, total savings shown.
4. **Paid tier** — all findings unlocked, full report, $19 one-time. (Link to landing page.)

### Priority 3: Test MCP in Claude Code
- Install deps: `pip install mcp pydantic boto3 anthropic python-dotenv`
- The `.mcp.json` is already configured for local stdio transport
- Test with Ravi's own AWS account (see credentials section below)
- Verify the full flow: inventory → costs → waste checks → report → dry-run → fix → verify

### Priority 4: Record demo
- Run `python demo.py` in a clean terminal
- Screen-record with OBS or QuickTime
- Trim to under 90 seconds
- This becomes the primary marketing asset

### Priority 5: Landing page + Razorpay checkout
- Single page at cloudcut.dev (or subdomain)
- Hero: "I cut my AWS bill from $265 to $128 in one session."
- Embed the demo video
- "Get full report — $19" button → Razorpay checkout
- Tech stack: Next.js (Ravi has done this 3x before — TrafficPruner, TradingBlindSpot, IdeaVerdict)
- Razorpay integration is already in Ravi's stack

### Priority 6: HTML report generator (reports/generator.py)
- Jinja2 template that takes findings JSON and renders an HTML report
- Same structure as the demo output but as a downloadable file
- Delivered via SendGrid after Razorpay payment webhook
- This is what the $19 buys

## AWS account context (founder's own account — used for testing and case study)

- Account ID: 180294215813
- IAM user: ravi_usr
- Primary region: ap-south-1
- Active infrastructure: AQS API on Fargate (cluster: aqs-prod, service: aqs-api-service) + RDS (aqs-db, db.t4g.micro) + ALB (aqs-alb)
- Domain: aqscore.in
- RegAssure: TORN DOWN. All RegAssure infrastructure (GPU instances, ALB, WAF, NAT gateway, RDS) has been deleted or terminated. Rebuilding from scratch later.

### What was found and fixed (the case study):
| Resource | Action | Savings |
|---|---|---|
| 200GB orphaned EBS (vol-0393fec8956c8f1f0) | Deleted | $18/mo |
| Unused EIP (eipalloc-08e78db7bc3055251) | Released | $4/mo |
| 500GB EBS on stopped g5.2xlarge | Snapshot → Delete | $46/mo |
| 300GB EBS on stopped g5.2xlarge | Snapshot → Delete | $27/mo |
| 100GB EBS on g4dn.xlarge (auto-deleted) | Terminated instance | $9/mo |
| g5.2xlarge (i-0ebfc1c240d8b62da) | Terminated | $0 (was stopped) |
| g4dn.xlarge (i-024f0356208a9cbb7) | Terminated | $0 (was stopped) |
| NAT Gateway (nat-002433986ecf9fe80) | Deleted | $22/mo |
| RegAssure ALB + target group | Deleted | $6/mo |
| RegAssure WAF | Deleted | $5/mo |
| **Total** | | **$137/mo saved** |
| **Before** | $265/mo | |
| **After** | ~$128/mo | |

## Tech stack and preferences

- **Backend:** FastAPI, Python, PostgreSQL, boto3
- **Frontend:** Next.js for landing pages
- **Payments:** Razorpay (already integrated in other products)
- **Email:** SendGrid
- **Hosting:** Render or AWS
- **LLM:** Claude (Anthropic SDK) — used in the MCP server for future Phase 2 code parsing, NOT used in the current rules engine (rules are deterministic)
- **MCP:** FastMCP (Python SDK), local stdio transport

## Architecture decisions (non-negotiable)

1. **Rules are deterministic, not LLM-driven.** The 5 launch checks use boto3 + arithmetic. No LLM in the analysis loop. This is for trust.
2. **Only 3 safe-fix classes.** SAFE_FIX_ALLOWLIST in `engine/allowlist.py`: orphaned_ebs, unassociated_eip, old_snapshot. Everything else returns a CLI command. Do not expand this list without explicit discussion.
3. **Human-in-the-loop for all fixes.** `confirm=true` must be set explicitly. Claude Code asks the user before every destructive action.
4. **Snapshot deletion is targeted.** Only deletes specific snapshot IDs from `finding.metadata.snapshot_ids`. No account-wide sweeps.
5. **Every action is logged.** Append-only JSONL at `~/.cloudcut/action_log.jsonl`. Dry-runs, confirmed, refused, failed — all recorded.
6. **Free tier shows top 3, paid shows all.** Gate is in `engine/tier_gate.py`. The engine runs all checks regardless of tier — the gate filters output only.
7. **Region is derived from resource, never hardcoded.** `Finding.region` is required (no default). All CLI commands use `finding.region`.

## What NOT to build right now

- More checks beyond the existing 9
- EC2/RDS/ECS auto-fix (not in allowlist)
- Code parser (Phase 2)
- Dashboard UI
- Authentication / RBAC
- CI/CD
- Tests (yes, really — not before first paying user)
- Multi-cloud
- Enterprise features

## MCP tool surface

| Tool | Purpose | Read-only? |
|---|---|---|
| `cloudcut_inventory_aws` | Scan resources | Yes |
| `cloudcut_analyze_costs` | Cost Explorer data | Yes |
| `cloudcut_run_waste_checks` | 5 deterministic checks | Yes |
| `cloudcut_generate_report` | Markdown/JSON report | Yes |
| `cloudcut_fix_finding` | Execute safe fixes (3 classes) | **No — destructive** |
| `cloudcut_verify_service` | Health check ECS/RDS/URL | Yes |
| `cloudcut_show_savings_summary` | Session action log | Yes |
| `cloudcut_scan_code_intent` | Phase 2 stub | N/A |
| `cloudcut_compare_code_vs_aws` | Phase 2 stub | N/A |

## Monetization

| Tier | Price | What they get |
|---|---|---|
| Free MCP | $0 | Top 3 findings, safe-fix for those 3, CLI commands for all, total savings shown |
| Full report | $19 | All findings unlocked, all safe-fixes, downloadable HTML report |
| Future: recurring | $29/mo | Weekly rescan, alerts, history (not built yet) |

## Ravi's other products (for context, not for this project)

- **TrafficPruner** — Google Ads waste diagnostic (trafficpruner.com). Same product pattern as CloudCut but for ad spend. Live with Razorpay.
- **AQS** — Address quality scoring API (aqscore.in). Live on AWS Fargate. 65/65 tests passing. Seeking NBFC pilot customers.
- **IdeaVerdict** — Instagram brand + ₹499 validation course. SuperProfile funnel.
- **RegAssure** — Regulatory compliance platform. Infrastructure torn down, rebuilding later.
- **Subra Spices** — D2C South Indian pickle/spice brand.

Ravi is a solo founder. 19 years in Indian financial services. Strong Python/LLM skills. Prefers direct, honest assessments. The GTM execution bottleneck is the pattern to be aware of — strong product architecture, distribution is the gap.
