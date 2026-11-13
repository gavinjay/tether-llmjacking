#!/usr/bin/env python3
"""Replay the leaked demo key from your own laptop, to show the audience it works from anywhere.

    eval "$(./demo.sh leak)"        # in CloudShell, then copy the two export lines to the laptop
    python3 replay_from_laptop.py --region us-east-1 --calls 5

Only ever point this at the llmjack-demo key in your own account. Needs: pip install boto3
"""
import argparse
import os
import sys

import boto3
from botocore.config import Config

p = argparse.ArgumentParser()
p.add_argument("--region", default="us-east-1")
p.add_argument("--model", default="amazon.nova-micro-v1:0")
p.add_argument("--calls", type=int, default=5)
a = p.parse_args()

if not os.environ.get("AWS_ACCESS_KEY_ID"):
    sys.exit("Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to the leaked demo key first.")

cfg = Config(region_name=a.region, retries={"max_attempts": 1})
print("whoami:", boto3.client("sts", config=cfg).get_caller_identity()["Arn"])
br = boto3.client("bedrock-runtime", config=cfg)
ok = denied = 0
for i in range(min(a.calls, 50)):
    try:
        r = br.converse(
            modelId=a.model,
            messages=[{"role": "user", "content": [{"text": "Write two sentences about llamas."}]}],
            inferenceConfig={"maxTokens": 60},
        )
        ok += 1
        print(f"  call {i + 1}: ALLOWED  {r['usage']['totalTokens']} tokens")
    except Exception as x:  # noqa: BLE001
        denied += 1
        print(f"  call {i + 1}: DENIED   {str(x)[:110]}")
print(f"\n{ok} allowed, {denied} denied ->", "KEY WORKS" if ok else "KEY IS USELESS")
