#!/usr/bin/env bash
# LLMjacking demo driver. Run it in AWS CloudShell in the Region where the stack lives.
#   ./demo.sh deploy            create the stack (about 4 minutes)
#   ./demo.sh run               the full story, start to finish
#   ./demo.sh app|exhibits|find|attack|lock|unlock|fixed|status|narrate   one step at a time
#   ./demo.sh scan              Tether Scan: read-only exposure check of this account
#   ./demo.sh guardduty-on|guardduty-samples|investigate|cost-watch   the newer AWS detection services
#   ./demo.sh ask "question"    ask the SOC narrator anything about the evidence
#   ./demo.sh leak              print the demo key as export lines, for a laptop replay
#   ./demo.sh park              disable the key between demos (unpark to re-enable)
#   ./demo.sh destroy           delete everything, including the local exhibits
set -euo pipefail
STACK=llmjack-demo
P=llmjack-demo
EX=./exhibits
KEYRE='AKIA[0-9A-Z]{16}'

call() {  # call <function-suffix> <json-payload>
  aws lambda invoke --function-name "$P-$1" --cli-binary-format raw-in-base64-out \
    --payload "$2" /tmp/$P-out.json >/dev/null
  python3 -m json.tool /tmp/$P-out.json
}
narrate() {
  aws lambda invoke --function-name "$P-soc-narrator" --cli-binary-format raw-in-base64-out \
    --payload "$1" /tmp/$P-out.json >/dev/null
  python3 -c "import json;print(json.load(open('/tmp/$P-out.json')).get('narrative','(no narrative)'))"
}
say()  { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
note() { printf '   %s\n' "$1"; }

# Builds the places a real company leaves this key lying around. All local to this CloudShell,
# nothing is pushed or published. It is the real demo key, so `destroy` and `park` matter.
exhibits() {
  aws lambda invoke --function-name "$P-control" --cli-binary-format raw-in-base64-out \
    --payload '{"action":"leak"}' /tmp/$P-key.json >/dev/null
  AK=$(python3 -c "import json;print(json.load(open('/tmp/$P-key.json'))['AWS_ACCESS_KEY_ID'])")
  SK=$(python3 -c "import json;print(json.load(open('/tmp/$P-key.json'))['AWS_SECRET_ACCESS_KEY'])")
  rm -f /tmp/$P-key.json
  rm -rf "$EX"; mkdir -p "$EX/gateway" "$EX/ci" "$EX/repo"

  # Exhibit A: git history. The key was committed, then "removed" in a later commit.
  ( cd "$EX/repo" && git init -q . \
    && printf 'AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\nAWS_REGION=us-east-1\n' "$AK" "$SK" > .env \
    && printf 'import boto3\n# LlamaDesk support bot\n' > bot.py \
    && git add -A && git -c user.name=dev -c user.email=dev@llamadesk.example commit -q -m "support bot v1" \
    && git rm -q .env && echo ".env" > .gitignore && git add -A \
    && git -c user.name=dev -c user.email=dev@llamadesk.example commit -q -m "oops, remove secrets" )

  # Exhibit B: LLM gateway config with the key pasted in, the quick way to wire up Bedrock.
  cat > "$EX/gateway/litellm_config.yaml" <<EOF
model_list:
  - model_name: support-bot
    litellm_params:
      model: bedrock/amazon.nova-micro-v1:0
      aws_access_key_id: $AK
      aws_secret_access_key: $SK
      aws_region_name: us-east-1
general_settings:
  master_key: sk-llamadesk-admin-1234
EOF

  # Exhibit C: a CI build log where a debug step printed the environment.
  cat > "$EX/ci/build-4821.log" <<EOF
[12:01:07] Step 3/9 : RUN pip install -r requirements.txt
[12:01:44] Step 4/9 : RUN env | sort   # debugging, remove later
[12:01:44] AWS_ACCESS_KEY_ID=$AK
[12:01:44] AWS_SECRET_ACCESS_KEY=$SK
[12:01:45] Step 5/9 : COPY . /app
EOF
  echo "Built exhibits A (git history), B (gateway config), C (CI log) under $EX"
}

# What a secret scanner sees. Attackers run the same kind of scan over public repos, images and logs.
scan() {
  [ -d "$EX" ] || { echo "Run ./demo.sh exhibits first"; exit 1; }
  say "Exhibit A: the repo today (the developer deleted the file)"
  grep -rnE "$KEYRE" "$EX/repo" --exclude-dir=.git | sed -E 's/(SECRET_ACCESS_KEY=....).*/\1****/' || note "clean: no key in the current files"
  say "Exhibit A: the same repo's history"
  git -C "$EX/repo" log -p --all | grep -nE "$KEYRE" | sed 's/^/   FOUND in an old commit: /' || true
  note "Deleting a secret in a new commit does not remove it from history."
  say "Exhibit B: LLM gateway config"
  grep -nE "$KEYRE" "$EX/gateway/litellm_config.yaml" | sed 's/^/   FOUND: /'
  say "Exhibit C: CI build log"
  grep -nE "$KEYRE" "$EX/ci/build-4821.log" | sed 's/^/   FOUND: /'
  say "Exhibit D: the running product's own configuration"
  aws lambda get-function-configuration --function-name "$P-app" --query 'Environment.Variables' --output json \
    | sed -E 's/("DEMO_SK": "....)[^"]*/\1****/'
  note "Anyone with read-only access to the account can read this. No break-in required."
  say "Same four places after the fix (role-based product)"
  aws lambda get-function-configuration --function-name "$P-app-fixed" --query 'Environment.Variables' --output json
  note "No key in the config, so there is nothing to commit, paste, print or steal."
}

case "${1:-help}" in
  deploy)
    aws cloudformation deploy --stack-name $STACK --template-file template.yaml \
      --capabilities CAPABILITY_NAMED_IAM ${2:+--parameter-overrides "${@:2}"}
    aws cloudformation describe-stacks --stack-name $STACK --query 'Stacks[0].Outputs' --output table ;;
  app)      call app "$(python3 -c 'import json,sys;print(json.dumps({"question":sys.argv[1]}))' "${2:-How do I reset my password?}")" ;;
  fixed)    call app-fixed "$(python3 -c 'import json,sys;print(json.dumps({"question":sys.argv[1]}))' "${2:-How do I reset my password?}")" ;;
  exhibits) exhibits ;;
  find)     scan ;;
  attack)   call attacker "{\"calls\": ${2:-12}, \"customers\": ${3:-3}}" ;;
  lock)     call control '{"action":"lock"}' ;;
  unlock)   call control '{"action":"unlock"}' ;;
  status)   call control '{"action":"status"}' ;;
  park)     call control '{"action":"disable"}'; rm -rf "$EX"; echo "Key disabled, local exhibits removed." ;;
  unpark)   call control '{"action":"enable"}' ;;
  narrate)  narrate "{\"minutes\": ${2:-60}}" ;;
  ask)      narrate "$(python3 -c 'import json,sys;print(json.dumps({"minutes":120,"question":sys.argv[1]}))' "$2")" ;;
  leak)
    aws lambda invoke --function-name "$P-control" --cli-binary-format raw-in-base64-out \
      --payload '{"action":"leak"}' /tmp/$P-out.json >/dev/null
    python3 -c "import json;[print(f'export {k}={v}') for k,v in json.load(open('/tmp/$P-out.json')).items()]"
    rm -f /tmp/$P-out.json ;;
  run)
    say "0. Reset: lock off, key on";  call control '{"action":"unlock"}'; call control '{"action":"enable"}'
    sleep 12   # IAM changes take a few seconds to apply everywhere
    say "ACT 1. The product. LlamaDesk's support bot answers a customer using Bedrock"
    call app '{"question":"How do I reset my password?"}'
    note "This is the victim: not AWS, but a company whose product calls an LLM from its backend."
    say "ACT 2. How the key got out. Nobody broke into anything"
    exhibits; scan
    say "ACT 3. THE EXPLOIT. A reseller uses the found key to serve its own paying customers"
    call attacker '{"calls": 12, "customers": 3}'
    note "Valid key, valid signature. AWS did exactly what it was asked. LlamaDesk gets the bill."
    say "ACT 4. Fix 1: the network lock. The key now only works from LlamaDesk's own VPC endpoint"
    call control '{"action":"lock"}'; sleep 15
    say "        Same reseller, same key";  call attacker '{"calls": 12, "customers": 3}'
    say "        The product is unaffected"; call app '{"question":"Where is my invoice?"}'
    say "ACT 5. Fix 2: no key at all. The product runs on an IAM role with temporary credentials"
    call app-fixed '{"question":"Can I change my plan?"}'
    note "Nothing to leak. Exhibits A to D would all come up empty."
    say "ACT 6. Waiting 2 minutes for CloudTrail to deliver the evidence"; sleep 120
    say "        SOC narrator"; narrate '{"minutes": 30}' ;;
  guardduty-on)   # turns on AI Protection and the Investigation preview. Account setting: fails in org-managed member accounts
    DET=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
    [ "$DET" = "None" ] && { echo "GuardDuty is not enabled in this Region."; exit 1; }
    aws guardduty update-detector --detector-id "$DET" \
      --features '[{"Name":"AI_PROTECTION","Status":"ENABLED"},{"Name":"AI_ANALYST","Status":"ENABLED"}]'
    aws guardduty get-detector --detector-id "$DET" \
      --query 'Features[?Name==`AI_PROTECTION` || Name==`AI_ANALYST`].[Name,Status]' --output table ;;
  guardduty-samples)   # real findings need a learned baseline, so show the shape with samples. They are labelled as samples
    DET=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
    aws guardduty create-sample-findings --detector-id "$DET" \
      --finding-types Impact:IAMUser/CostHarvesting Impact:IAMUser/AnomalousModelInvocation
    echo "Sample findings requested. They reach the dashboard within a few minutes." ;;
  investigate)   # GuardDuty Investigation (preview): AWS's AI analyst. Pass a finding ID, or nothing for an account-level review
    DET=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
    ACCT=$(aws sts get-caller-identity --query Account --output text)
    PROMPT="Investigate account $ACCT for misuse of Amazon Bedrock with compromised credentials"
    [ -n "${2:-}" ] && PROMPT="Investigate finding $2 in account $ACCT"
    ID=$(aws guardduty create-investigation --detector-id "$DET" --trigger-prompt "$PROMPT" --query InvestigationId --output text)
    echo "Investigation $ID started. It runs in the background. Fetch it with:"
    echo "  aws guardduty get-investigation --detector-id $DET --investigation-id $ID" ;;
  cost-watch)   # Cost Anomaly Detection on Bedrock spend, alerting the demo SNS topic
    TOPIC=$(aws sns list-topics --query "Topics[?ends_with(TopicArn, ':llmjack-demo-alerts')].TopicArn | [0]" --output text)
    MON=$(aws ce create-anomaly-monitor --region us-east-1 --query MonitorArn --output text --anomaly-monitor \
      '{"MonitorName":"llmjack-demo-bedrock","MonitorType":"CUSTOM","MonitorSpecification":{"Dimensions":{"Key":"SERVICE","Values":["Amazon Bedrock"]}}}')
    aws ce create-anomaly-subscription --region us-east-1 --anomaly-subscription \
      "{\"SubscriptionName\":\"llmjack-demo-bedrock\",\"MonitorArnList\":[\"$MON\"],\"Subscribers\":[{\"Type\":\"SNS\",\"Address\":\"$TOPIC\"}],\"Frequency\":\"IMMEDIATE\",\"ThresholdExpression\":{\"Dimensions\":{\"Key\":\"ANOMALY_TOTAL_IMPACT_ABSOLUTE\",\"MatchOptions\":[\"GREATER_THAN_OR_EQUAL\"],\"Values\":[\"1\"]}}}"
    echo "Monitor $MON created. Remove it with: aws ce delete-anomaly-monitor --region us-east-1 --monitor-arn $MON" ;;
  scan)  shift; python3 tether_scan.py "$@" ;;
  destroy)
    rm -rf "$EX"
    call control '{"action":"unlock"}' || true   # an attached policy would block deleting the user
    aws cloudformation delete-stack --stack-name $STACK
    aws cloudformation wait stack-delete-complete --stack-name $STACK && echo "Deleted." ;;
  *) sed -n '2,12p' "$0" ;;
esac
