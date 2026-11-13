#!/usr/bin/env python3
"""Tether Scan: a read-only check of how exposed an AWS account is to stolen-key abuse of Amazon Bedrock.

    python3 tether_scan.py                 # scan the current account and Region (CloudShell works)
    python3 tether_scan.py --regions us-east-1 us-west-2 --out report

It only calls List/Get/Describe APIs. It changes nothing and reads no secret values.
A check that cannot run (missing permission, service not enabled) is reported as UNKNOWN, never as a pass.

Sections follow the four things AWS asks partners to help startups with:
  1. access key hygiene   2. roles instead of long-lived keys   3. detection and cost alerts   4. review readiness
"""
import argparse
import csv
import datetime as dt
import io
import json
import sys
import time

MAX_KEY_AGE_DAYS = 90
STALE_DAYS = 90
BROAD_BEDROCK_POLICIES = ("AmazonBedrockFullAccess", "AmazonBedrockLimitedAccess")
NOW = dt.datetime.now(dt.timezone.utc)

findings = []


def add(section, severity, title, evidence, fix):
    """severity: HIGH, MEDIUM, LOW, OK or UNKNOWN."""
    findings.append({"section": section, "severity": severity, "title": title, "evidence": evidence, "fix": fix})


def unknown(section, what, err):
    add(section, "UNKNOWN", f"Could not check: {what}", str(err)[:160], "Re-run with a role that has read access to this service.")


def days_since(ts):
    """Age in whole days of an ISO timestamp from the IAM credential report. None for N/A or empty."""
    if not ts or ts in ("N/A", "no_information", "not_supported"):
        return None
    return (NOW - dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))).days


def assess_key(user, n, active, rotated, last_used):
    """Pure function: classify one access key from credential-report fields. Returns (severity, title, evidence) or None."""
    if active != "true":
        return None
    age, idle = days_since(rotated), days_since(last_used)
    if idle is None:
        return ("HIGH", f"Active access key never used: {user} (key {n})",
                f"Created {age} days ago, no recorded use. An unused active key is pure risk.")
    if age is not None and age > MAX_KEY_AGE_DAYS and idle > STALE_DAYS:
        return ("HIGH", f"Old and dormant access key: {user} (key {n})", f"{age} days old, last used {idle} days ago.")
    if age is not None and age > MAX_KEY_AGE_DAYS:
        return ("MEDIUM", f"Long-lived access key in active use: {user} (key {n})",
                f"{age} days old, last used {idle} days ago. This is the kind of key that ends up in a repo or config file.")
    return ("LOW", f"Active access key: {user} (key {n})", f"{age} days old, last used {idle} days ago.")


def credential_report(iam):
    for _ in range(10):
        if iam.generate_credential_report()["State"] == "COMPLETE":
            break
        time.sleep(2)
    content = iam.get_credential_report()["Content"]
    text = content.decode() if isinstance(content, (bytes, bytearray)) else str(content)
    return list(csv.DictReader(io.StringIO(text)))


def check_keys(session):
    s = "1. Access key hygiene"
    iam = session.client("iam")
    try:
        rows = credential_report(iam)
        n_keys = 0
        for r in rows:
            for n in ("1", "2"):
                res = assess_key(r["user"], n, r.get(f"access_key_{n}_active"), r.get(f"access_key_{n}_last_rotated"),
                                 r.get(f"access_key_{n}_last_used_date"))
                if res:
                    n_keys += 1
                    fix = ("Delete it." if "never used" in res[1] or "dormant" in res[1]
                           else "Move the workload to an IAM role with temporary credentials, then delete the key.")
                    if r["user"] == "<root_account>":
                        res, fix = ("HIGH", "Root account has an active access key", res[2]), "Delete the root access key."
                    add(s, res[0], res[1], res[2], fix)
            if r["user"] == "<root_account>" and r.get("mfa_active") != "true":
                add(s, "HIGH", "Root account has no MFA", "mfa_active is false in the credential report.", "Enable MFA on the root user.")
        if n_keys == 0:
            add(s, "OK", "No active long-lived IAM access keys", f"{len(rows)} identities checked.", "Nothing to do.")
    except Exception as e:
        unknown(s, "IAM credential report", e)
    try:
        acct = session.client("account")
        for kind in ("SECURITY", "BILLING", "OPERATIONS"):
            try:
                acct.get_alternate_contact(AlternateContactType=kind)
            except acct.exceptions.ResourceNotFoundException:
                add(s, "MEDIUM", f"No {kind.lower()} alternate contact", "AWS abuse and billing notices go only to the root email.",
                    f"Set a {kind.lower()} alternate contact so AWS can reach a human quickly.")
    except Exception as e:
        unknown(s, "alternate contacts", e)


def check_bedrock_access(session, regions):
    s = "2. Roles instead of long-lived keys"
    iam = session.client("iam")
    try:
        with_keys = []
        for page in iam.get_paginator("list_users").paginate():
            for u in page["Users"]:
                creds = iam.list_service_specific_credentials(UserName=u["UserName"], ServiceName="bedrock.amazonaws.com")
                active = [c for c in creds.get("ServiceSpecificCredentials", []) if c.get("Status") == "Active"]
                if active:
                    with_keys.append(f"{u['UserName']} ({len(active)})")
        if with_keys:
            add(s, "HIGH", "Long-term Bedrock API keys exist", ", ".join(with_keys[:15]),
                "Replace with short-term keys or IAM roles, then block long-term keys with the policy in policies/.")
        else:
            add(s, "OK", "No long-term Bedrock API keys", "No active Bedrock service-specific credentials on any IAM user.", "Nothing to do.")
    except Exception as e:
        unknown(s, "long-term Bedrock API keys", e)
    try:
        for name in BROAD_BEDROCK_POLICIES:
            ents = iam.list_entities_for_policy(PolicyArn=f"arn:aws:iam::aws:policy/{name}")
            users = [u["UserName"] for u in ents.get("PolicyUsers", [])]
            if users:
                add(s, "HIGH", f"IAM users hold {name}", ", ".join(users[:15]),
                    "Scope each identity to the specific models it calls. A leaked key inherits everything this policy allows.")
    except Exception as e:
        unknown(s, "broad Bedrock policies on users", e)
    for region in regions:
        try:
            eps = session.client("ec2", region_name=region).describe_vpc_endpoints(
                Filters=[{"Name": "service-name", "Values": [f"com.amazonaws.{region}.bedrock-runtime"]}])["VpcEndpoints"]
            if eps:
                add(s, "OK", f"Bedrock VPC endpoint present in {region}", ", ".join(e["VpcEndpointId"] for e in eps),
                    "Pin Bedrock access to it with an aws:SourceVpce condition so stolen credentials fail elsewhere.")
            else:
                add(s, "MEDIUM", f"No Bedrock VPC endpoint in {region}", "Bedrock is reached over the public endpoint, so access cannot be tied to your network.",
                    "Add an interface endpoint for bedrock-runtime and restrict access to it.")
        except Exception as e:
            unknown(s, f"Bedrock VPC endpoints in {region}", e)


def check_detection(session, regions):
    s = "3. Detection and cost alerts"
    for region in regions:
        try:
            gd = session.client("guardduty", region_name=region)
            dets = gd.list_detectors()["DetectorIds"]
            if not dets:
                add(s, "HIGH", f"GuardDuty is not enabled in {region}", "No detector.", "Enable GuardDuty, then AI Protection.")
            else:
                feats = {f["Name"]: f["Status"] for f in gd.get_detector(DetectorId=dets[0]).get("Features", [])}
                for feat, label, why in (("AI_PROTECTION", "GuardDuty AI Protection", "Detects cost harvesting and anomalous model invocations."),
                                         ("AI_ANALYST", "GuardDuty Investigation (preview)", "AI-written investigation of a finding or account.")):
                    if feats.get(feat) == "ENABLED":
                        add(s, "OK", f"{label} is on in {region}", f"{feat}=ENABLED", "Route its low-severity findings somewhere a human looks.")
                    else:
                        add(s, "HIGH" if feat == "AI_PROTECTION" else "LOW", f"{label} is off in {region}",
                            f"{feat}={feats.get(feat, 'not present')}. {why}", f"Enable the {feat} feature on the detector.")
        except Exception as e:
            unknown(s, f"GuardDuty in {region}", e)
        try:
            cfg = session.client("bedrock", region_name=region).get_model_invocation_logging_configuration().get("loggingConfig")
            if cfg:
                add(s, "OK", f"Bedrock model invocation logging is on in {region}", "A logging destination is configured.", "Restrict who can read the logs: they contain prompts.")
            else:
                add(s, "MEDIUM", f"Bedrock model invocation logging is off in {region}", "No loggingConfig. Investigations will lack per-request detail.",
                    "Enable it to CloudWatch Logs or S3.")
        except Exception as e:
            unknown(s, f"Bedrock invocation logging in {region}", e)
    try:
        ce = session.client("ce", region_name="us-east-1")
        mons = ce.get_anomaly_monitors().get("AnomalyMonitors", [])
        subs = ce.get_anomaly_subscriptions().get("AnomalySubscriptions", [])
        if mons and subs:
            add(s, "OK", "Cost Anomaly Detection has monitors and subscribers", f"{len(mons)} monitors, {len(subs)} subscriptions.", "Confirm the subscribers are current.")
        else:
            add(s, "HIGH", "Cost Anomaly Detection will not alert anyone", f"{len(mons)} monitors, {len(subs)} subscriptions.",
                "Create a subscription with an immediate alert. It now covers third-party Bedrock models too.")
    except Exception as e:
        unknown(s, "Cost Anomaly Detection", e)
    try:
        acct_id = session.client("sts").get_caller_identity()["Account"]
        bud = session.client("budgets", region_name="us-east-1")
        budgets = bud.describe_budgets(AccountId=acct_id).get("Budgets", [])
        actions = bud.describe_budget_actions_for_account(AccountId=acct_id).get("Actions", [])
        if not budgets:
            add(s, "HIGH", "No AWS Budgets", "Nothing alerts on total spend.", "Add a budget for Bedrock with an alert, and consider a budget action.")
        elif not actions:
            add(s, "MEDIUM", "Budgets alert but cannot stop spend", f"{len(budgets)} budgets, 0 budget actions. Bedrock has no spending cap by default.",
                "Add a budget action that applies a deny policy to the Bedrock-calling identities.")
        else:
            add(s, "OK", "Budgets with actions exist", f"{len(budgets)} budgets, {len(actions)} actions.", "Check one covers Bedrock.")
    except Exception as e:
        unknown(s, "AWS Budgets", e)


def check_review_readiness(session, regions):
    s = "4. Review readiness"
    region = regions[0]
    try:
        session.client("securityhub", region_name=region).describe_hub()
        add(s, "OK", f"Security Hub is enabled in {region}", "Hub found.", "Use its unused-access findings as the clean-up list for dormant keys and roles.")
    except Exception as e:
        if "not subscribed" in str(e) or "InvalidAccessException" in str(e):
            add(s, "MEDIUM", f"Security Hub is not enabled in {region}", "No hub.", "Enable it to get unused-access and exposure findings in one place.")
        else:
            unknown(s, "Security Hub", e)
    try:
        an = session.client("accessanalyzer", region_name=region).list_analyzers().get("analyzers", [])
        kinds = sorted({a["type"] for a in an})
        if any("UNUSED_ACCESS" in k for k in kinds):
            add(s, "OK", "An unused-access analyzer exists", ", ".join(kinds), "Review its findings for dormant keys.")
        else:
            add(s, "LOW", "No unused-access analyzer", f"Analyzers: {', '.join(kinds) or 'none'}.", "Security Hub can now surface unused access across the organization.")
    except Exception as e:
        unknown(s, "IAM Access Analyzer", e)


ORDER = {"HIGH": 0, "MEDIUM": 1, "UNKNOWN": 2, "LOW": 3, "OK": 4}


def render(account, regions):
    counts = {k: sum(1 for f in findings if f["severity"] == k) for k in ORDER}
    out = [f"# Tether Scan: account {account}", "",
           f"Run {NOW:%Y-%m-%d %H:%M} UTC. Regions: {', '.join(regions)}. Read-only.", "",
           f"**{counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['LOW']} low, {counts['OK']} ok, {counts['UNKNOWN']} could not be checked.**", ""]
    for section in sorted({f["section"] for f in findings}):
        out += [f"## {section}", "", "| Severity | Finding | Evidence | Fix |", "|---|---|---|---|"]
        for f in sorted((f for f in findings if f["section"] == section), key=lambda f: ORDER[f["severity"]]):
            out.append(f"| {f['severity']} | {f['title']} | {f['evidence']} | {f['fix']} |".replace("\n", " "))
        out.append("")
    out.append("UNKNOWN means the check could not run. It is not a pass.")
    return "\n".join(out)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--regions", nargs="+", help="Regions to check. Default: the session's Region.")
    p.add_argument("--profile")
    p.add_argument("--out", default="tether-scan", help="Output file stem. Writes <stem>.md and <stem>.json")
    a = p.parse_args()
    import boto3
    session = boto3.Session(profile_name=a.profile) if a.profile else boto3.Session()
    regions = a.regions or [session.region_name or "us-east-1"]
    try:
        account = session.client("sts").get_caller_identity()["Account"]
    except Exception as e:
        sys.exit(f"No usable AWS credentials: {e}")
    check_keys(session)
    check_bedrock_access(session, regions)
    check_detection(session, regions)
    check_review_readiness(session, regions)
    report = render(account, regions)
    open(a.out + ".md", "w").write(report)
    json.dump({"account": account, "regions": regions, "run": NOW.isoformat(), "findings": findings}, open(a.out + ".json", "w"), indent=2)
    print(report)
    print(f"\nWrote {a.out}.md and {a.out}.json")


if __name__ == "__main__":
    main()
