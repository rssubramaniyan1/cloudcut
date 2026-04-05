#!/usr/bin/env python3
"""
CloudCut Demo — End-to-End Flow
════════════════════════════════
Uses real findings from account 180294215813 (ap-south-1).
Run this, screen-record it. That's your demo.

Usage:
  python demo.py
"""
import json
import time
import sys
import os

# ─── Simulated data from Ravi's actual account (April 5, 2026) ───

ACCOUNT = "180294215813"
REGION = "ap-south-1"

COST_DATA = {
    "total_spend": 265.32,
    "top_services": [
        {"service": "EC2 - Other", "spend": 143.39},
        {"service": "Tax", "spend": 40.48},
        {"service": "Amazon Elastic Compute Cloud", "spend": 30.52},
        {"service": "Amazon Relational Database Service", "spend": 12.66},
        {"service": "Amazon Virtual Private Cloud", "spend": 10.28},
        {"service": "Amazon Elastic Load Balancing", "spend": 10.28},
        {"service": "AWS WAF", "spend": 4.09},
        {"service": "Amazon Elastic Container Service", "spend": 3.42},
        {"service": "Amazon Simple Storage Service", "spend": 3.15},
    ],
}

FINDINGS = [
    {
        "finding_id": "f_ebs_001",
        "title": "Unattached EBS volume (200GB gp3)",
        "resource_id": "vol-0393fec8956c8f1f0",
        "finding_type": "orphaned_ebs",
        "severity": "high",
        "action": "terminate",
        "monthly_savings": 18.00,
        "confidence": "95%",
        "confidence_band": "high",
        "risk": "low",
        "safe_fixable": True,
        "summary": "EBS volume has no attached instance. Created 2025-06-18, unattached for ~10 months.",
        "before_state": {
            "resource": "vol-0393fec8956c8f1f0",
            "type": "EBS Volume",
            "state": "available (unattached)",
            "billing": "$18.00/mo",
        },
        "after_state": {
            "resource": "vol-0393fec8956c8f1f0",
            "state": "DELETED",
            "billing": "$0/mo",
            "note": "Safety snapshot created first.",
        },
        "cli": "aws ec2 delete-volume --volume-id vol-0393fec8956c8f1f0 --region ap-south-1",
    },
    {
        "finding_id": "f_eip_001",
        "title": "Unassociated Elastic IP (13.233.33.195)",
        "resource_id": "eipalloc-08e78db7bc3055251",
        "finding_type": "unassociated_eip",
        "severity": "medium",
        "action": "terminate",
        "monthly_savings": 3.60,
        "confidence": "95%",
        "confidence_band": "high",
        "risk": "low",
        "safe_fixable": True,
        "summary": "Elastic IP not attached to any instance or ENI. Billed $3.60/mo since Feb 2024.",
        "before_state": {
            "resource": "eipalloc-08e78db7bc3055251",
            "type": "Elastic IP",
            "state": "unassociated",
            "billing": "$3.60/mo",
        },
        "after_state": {
            "resource": "eipalloc-08e78db7bc3055251",
            "state": "RELEASED",
            "billing": "$0/mo",
        },
        "cli": "aws ec2 release-address --allocation-id eipalloc-08e78db7bc3055251 --region ap-south-1",
    },
    {
        "finding_id": "f_ec2_001",
        "title": "Idle GPU instance (g5.2xlarge) — stopped with 800GB EBS",
        "resource_id": "i-0ebfc1c240d8b62da",
        "finding_type": "idle_ec2",
        "severity": "critical",
        "action": "stop_schedule",
        "monthly_savings": 73.00,
        "confidence": "88%",
        "confidence_band": "high",
        "risk": "low",
        "safe_fixable": False,
        "summary": "Stopped g5.2xlarge with 800GB attached EBS (300GB + 500GB). LLM fine-tuning weights saved to S3. Volumes billing $73/mo.",
        "before_state": {
            "resource": "i-0ebfc1c240d8b62da",
            "type": "EC2 + EBS",
            "state": "stopped (volumes still billing)",
            "billing": "$73.00/mo",
        },
        "cli": "aws ec2 terminate-instances --instance-ids i-0ebfc1c240d8b62da --region ap-south-1",
    },
    {
        "finding_id": "f_nat_001",
        "title": "NAT Gateway — zero traffic, $22/mo",
        "resource_id": "nat-002433986ecf9fe80",
        "finding_type": "nat_gateway_anomaly",
        "severity": "high",
        "action": "review_architecture",
        "monthly_savings": 22.00,
        "confidence": "70%",
        "confidence_band": "medium",
        "risk": "medium",
        "safe_fixable": False,
        "summary": "NAT Gateway in ap-south-1a. Fargate AQS has assignPublicIp=ENABLED — NAT is unused.",
        "cli": "aws ec2 delete-nat-gateway --nat-gateway-id nat-002433986ecf9fe80 --region ap-south-1",
    },
]


# ─── Output helpers ───

G = "\033[32m"  # green
Y = "\033[33m"  # yellow
R = "\033[31m"  # red
C = "\033[36m"  # cyan
B = "\033[1m"   # bold
D = "\033[2m"   # dim
X = "\033[0m"   # reset


def type_out(text, delay=0.01):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def section(title):
    print(f"\n{D}{'─' * 60}{X}")
    print(f"{B}{C}{title}{X}")
    print(f"{D}{'─' * 60}{X}\n")


def tool_call(name):
    print(f"  {D}→ calling{X} {C}{name}{X}")
    time.sleep(0.5)


def pause(msg=""):
    if msg:
        print(f"\n  {D}{msg}{X}")
    input(f"  {D}[press Enter to continue]{X}")


# ─── Demo Flow ───

def main():
    os.system("clear" if os.name != "nt" else "cls")

    print(f"""
{B}  ╔══════════════════════════════════════════════╗
  ║  CloudCut — AWS Cost Diagnostics Demo        ║
  ║  Account: {ACCOUNT}  Region: {REGION}  ║
  ╚══════════════════════════════════════════════╝{X}
""")

    pause("Starting scan...")

    # ─── Step 1: Inventory ───
    section("Step 1 → cloudcut_inventory_aws")
    tool_call("cloudcut_inventory_aws")
    time.sleep(1)

    print(f"""  {G}✓ Inventory complete{X}

  Resources found:
    ec2_instance     {B}2{X}
    ebs_volume       {B}4{X}  {Y}← 1 unattached{X}
    elastic_ip       {B}1{X}  {Y}← unassociated{X}
    rds_instance     {B}2{X}
    ecs_service      {B}1{X}  (aqs-api-service)
    nat_gateway      {B}1{X}
""")

    pause()

    # ─── Step 2: Costs ───
    section("Step 2 → cloudcut_analyze_costs")
    tool_call("cloudcut_analyze_costs")
    time.sleep(0.8)

    print(f"  Monthly spend: {B}{R}$265.32{X}\n")
    print(f"  {'Service':<40} {'Spend':>10}")
    print(f"  {D}{'─' * 52}{X}")
    for s in COST_DATA["top_services"]:
        bar = "█" * int(s["spend"] / 5)
        color = R if s["spend"] > 50 else Y if s["spend"] > 10 else D
        print(f"  {s['service']:<40} {color}${s['spend']:>8.2f}{X}  {D}{bar}{X}")

    pause()

    # ─── Step 3: Waste checks ───
    section("Step 3 → cloudcut_run_waste_checks")
    tool_call("cloudcut_run_waste_checks")
    time.sleep(1.2)

    total_savings = sum(f["monthly_savings"] for f in FINDINGS)
    safe_count = sum(1 for f in FINDINGS if f["safe_fixable"])
    report_count = len(FINDINGS) - safe_count

    print(f"""  {G}✓ {len(FINDINGS)} findings{X}  •  {G}${total_savings:.2f}/mo savings{X}  •  {G}${total_savings*12:.2f}/yr{X}
  {safe_count} safe-fixable  •  {report_count} report-only
""")

    for i, f in enumerate(FINDINGS):
        sev = {"critical": f"{R}CRIT{X}", "high": f"{Y}HIGH{X}", "medium": f"{D}MED {X}"}.get(f["severity"], "")
        fix = f"{G}✅ safe-fix{X}" if f["safe_fixable"] else f"{D}📋 manual{X}"
        print(f"  {B}P{i+1}{X}  {sev}  {fix}  {B}${f['monthly_savings']:>6.2f}/mo{X}")
        print(f"      {f['title']}")
        print(f"      {D}`{f['resource_id']}`  •  {f['confidence']} confidence  •  {f['risk']} risk{X}")
        print()

    pause()

    # ─── Step 4: Dry run ───
    section("Step 4 → cloudcut_fix_finding (DRY RUN)")

    f = FINDINGS[0]  # orphaned EBS
    tool_call(f"cloudcut_fix_finding(finding_id='{f['finding_id']}', confirm=false)")
    time.sleep(0.8)

    print(f"""
  {Y}╔══════════════════════════════════════════════════╗
  ║  DRY RUN — no changes made                       ║
  ╚══════════════════════════════════════════════════╝{X}

  Finding:   {f['title']}
  Resource:  {C}{f['resource_id']}{X}
  Action:    {f['action']}
  Savings:   {G}${f['monthly_savings']:.2f}/mo{X}  •  ${f['monthly_savings']*12:.2f}/yr

  {B}Before:{X}
    State:   {R}available (unattached){X}
    Billing: {R}$18.00/mo{X}

  {B}After:{X}
    State:   {G}DELETED{X}
    Billing: {G}$0/mo{X}
    Note:    Safety snapshot created first

  {D}Rollback: Create volume from snapshot if data needed{X}
  {D}CLI:      {f['cli']}{X}

  {D}Logged to: ~/.cloudcut/action_log.jsonl (mode: dry_run){X}
""")

    pause("Ready to confirm?")

    # ─── Step 5: Confirm ───
    section("Step 5 → cloudcut_fix_finding (CONFIRMED)")

    tool_call(f"cloudcut_fix_finding(finding_id='{f['finding_id']}', confirm=true)")
    print(f"  {D}Creating safety snapshot...{X}")
    time.sleep(0.8)
    print(f"  {D}Snapshot snap-0a1b2c3d completed.{X}")
    time.sleep(0.5)
    print(f"  {D}Deleting volume {f['resource_id']}...{X}")
    time.sleep(0.5)

    print(f"""
  {G}╔══════════════════════════════════════════════════╗
  ║  COMPLETED                                        ║
  ╚══════════════════════════════════════════════════╝{X}

  Resource:  {C}{f['resource_id']}{X}  →  {G}DELETED{X}
  Snapshot:  {C}snap-0a1b2c3d{X}  (safety backup)
  Saved:     {G}${f['monthly_savings']:.2f}/mo{X}

  {D}Logged to: ~/.cloudcut/action_log.jsonl (mode: confirmed){X}
""")

    pause()

    # ─── Step 6: Verify ───
    section("Step 6 → cloudcut_verify_service")
    tool_call("cloudcut_verify_service(check_type='all', url='https://aqscore.in/docs')")
    time.sleep(1)

    print(f"""
  ECS  aqs-api-service    desired=1  running=1  {G}● healthy{X}
  RDS  aqs-db             db.t4g.micro           {G}● healthy{X}
  RDS  regassure-db       db.t3.micro            {G}● healthy{X}
  URL  aqscore.in/docs    HTTP 200               {G}● healthy{X}

  Overall: {G}{B}healthy{X}  — no services affected
""")

    pause()

    # ─── Step 7: Summary ───
    section("Step 7 → cloudcut_show_savings_summary")
    tool_call("cloudcut_show_savings_summary")
    time.sleep(0.5)

    print(f"""
  {G}✅ Confirmed Fixes{X}

    {G}✓{X}  vol-0393fec8956c8f1f0  orphaned_ebs     {G}$18.00/mo{X}  (backup: snap-0a1b2c3d)

  {D}📋 Remaining (manual CLI){X}

    eipalloc-08e78db7bc3055251   unassociated_eip   $3.60/mo   low risk
    i-0ebfc1c240d8b62da          idle_ec2           $73.00/mo  low risk
    nat-002433986ecf9fe80        nat_gateway        $22.00/mo  medium risk

  ┌─────────────────────────────────────────┐
  │  {G}{B}Saved this session:    $18.00/mo{X}       │
  │  {D}Remaining actionable:  $98.60/mo{X}       │
  │  {D}Total potential:       $116.60/mo{X}      │
  │  {G}{B}Annual projection:     $1,399.20{X}       │
  └─────────────────────────────────────────┘
""")

    print(f"""{D}{'─' * 60}{X}
{B}Demo complete.{X}

Full session logged to {C}~/.cloudcut/action_log.jsonl{X}
Every action — dry-run, confirmed, refused — is recorded.

{B}Product:{X} CloudCut — Scan your AWS for waste. Fix low-risk issues with approval.
{B}Price:{X}  Free scan (top 3) → $19 full report → all findings + CLI commands.
{D}{'─' * 60}{X}
""")


if __name__ == "__main__":
    main()
