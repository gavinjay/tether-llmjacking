# Tether: LLMjacking protection for Amazon Bedrock

A stolen key that only works at home is just a string. Tether ties a product's Bedrock access to its own
network, then removes the key altogether. This repo is the working demo.

A six-act demo: a startup's product leaks its Bedrock key, a reseller cashes in on it, the key is
made useless, and then the key is removed altogether. With a dashboard and a SOC narrator.

**Status: built and validated offline (template lint clean, Lambda code parses, the leak exhibits and
scan step run locally against a fake key). Not yet deployed or run against a live AWS account.**
The first deploy is the real test. See "Things the first run will confirm".

## The one idea to land

**This is not a hack against AWS.** It is a hack against a company whose product uses an LLM in its
backend: a chatbot, a copilot, a support tool, an agent. That backend needs a credential to call the
model. If the company stores a long-lived key, the key ends up copied into repos, config files, build
logs and laptops. Someone finds a copy and uses it.

Every call the attacker makes is a valid, correctly signed request with the company's own key. AWS does
exactly what it is asked, and the company pays. Under the shared responsibility model, where the key
lives is the customer's side of the line. That is why the fix is something a partner delivers, not
something AWS can switch on for them.

The victim in the demo is **LlamaDesk**, a made-up startup with a support bot.

## The six acts (`./demo.sh run`)

| Act | What the audience sees | The point |
|---|---|---|
| 1. The product | A customer question goes in, the bot answers using Bedrock | The victim is an ordinary company with an LLM feature |
| 2. How the key got out | Four exhibits, each with the key sitting in it | Nobody broke in. The key was left lying around |
| 3. The exploit | A reseller serves three of its own paying customers off the key | They want quiet, lasting access to resell. The bill is a side effect |
| 4. Fix 1: network lock | Same reseller, same key: denied. Product still works | A leaked key is useless outside the company's own network |
| 5. Fix 2: no key | The product runs on an IAM role. The exhibits come up empty | The best key is one that does not exist |
| 6. SOC narrator | Plain-language walkthrough of the timeline from the evidence | Detection and a story the customer's team can follow |

### Act 2 exhibits

| Exhibit | Where the key is | Lesson |
|---|---|---|
| A. Git history | Committed in `.env`, then deleted in a later commit | Deleting a secret does not remove it from history |
| B. LLM gateway config | Pasted into `litellm_config.yaml` to wire up Bedrock | One file ends up holding every provider's keys |
| C. CI build log | A debug step printed the environment | Logs are read by more people and tools than code is |
| D. The running product's config | Plain-text environment variable | Anyone with read-only account access can see it |

The exhibits are files created locally in CloudShell. Nothing is pushed or published. They contain the
real demo key, so run `./demo.sh park` when you are done: it disables the key and deletes them.

Not simulated, but worth saying out loud: poisoned dependencies that read the environment, infected
developer laptops, and exposed gateway admin pages.

## What gets created

| Piece | What it is |
|---|---|
| Product (as shipped) | Lambda in a private VPC calling Bedrock through a VPC endpoint with a long-lived IAM user key |
| Product (fixed) | The same code on an IAM role, with no key anywhere |
| Attacker | Lambda outside the VPC acting as a reseller. Our simulated attacker is capped at 100 small calls per run so the demo itself stays cheap. Real attackers have no such limit, and Bedrock has no spending cap by default |
| Network lock | IAM policy that denies Bedrock unless the call arrives through that one VPC endpoint |
| Collector | EventBridge rule on CloudTrail catches every call, labels it, and can apply the lock automatically |
| Dashboard | `llmjack-demo`: legit, stolen, blocked and role-based calls per minute, who the key was resold to, incidents |
| SOC narrator | Lambda that reads the evidence, writes the walkthrough and answers follow-up questions |
| Cost attribution tags | The product's IAM user and role carry `team` and `project` tags, for Bedrock cost allocation by IAM principal. Activate the tags in Billing to see spend per identity |

Everything is named `llmjack-demo*`. The key and the role can only invoke Amazon Nova models.

## Deploy (AWS CloudShell, with a role that can create IAM, Lambda, VPC and EventBridge resources)

1. Upload `template.yaml` and `demo.sh` to CloudShell (Actions, Upload file).
2. `chmod +x demo.sh && ./demo.sh deploy`
3. `./demo.sh run`
4. Open the dashboard URL printed by the deploy step.

Pick a Region where the model in `ModelId` can be called directly. To use an inference profile instead:
`./demo.sh deploy ModelId=us.amazon.nova-micro-v1:0 NarratorModelId=us.amazon.nova-lite-v1:0`

Self-healing variant, where detection applies the lock on its own: `./demo.sh deploy AutoContain=true`

Each act can be run alone: `app`, `exhibits`, `scan`, `attack`, `lock`, `unlock`, `fixed`, `narrate`.
For extra effect, replay the key from your own laptop: `./demo.sh leak`, copy the two export lines
to the laptop, then `python3 replay_from_laptop.py`.

Ask the narrator anything: `./demo.sh ask "Who was the key resold to and how many calls did each make?"`

## What the lock does not stop (say this before someone asks)

- An attacker running code inside the company's own systems, calling Bedrock through the real endpoint.
- A stolen LLM gateway key. The gateway makes the call from inside the network on the attacker's behalf.
- A stolen key that also has IAM rights and can simply detach the lock.

Act 5 answers the first and third. The gateway case needs gateway hardening: keep it off the public
internet, cap spend per key, keep the master key in Secrets Manager.

## GuardDuty AI Protection (not in the template)

It is an account or organization setting, so it is left for you to switch on:
GuardDuty console, Protection plans, AI Protection, Enable. Its findings come from learned baselines,
so they will not fire on cue during a ten-minute demo. Use `aws guardduty create-sample-findings` to show
what a finding looks like, and say so on stage.

## Things the first run will confirm

- The model IDs are enabled and callable in the chosen Region.
- `aws:SourceVpce` behaves as expected when the model is called through an inference profile.
- CloudTrail delivers denied `Converse` calls to EventBridge, with `vpcEndpointId` present for in-VPC calls.
- The reseller tag in the user agent shows up in CloudTrail (the "resold to" dashboard panel depends on it).
- The Bedrock endpoint is offered in the first Availability Zone (if not, deploy with `AzIndex=1`).

## Between demos and teardown

- `./demo.sh park` disables the key and removes the local exhibits. `./demo.sh unpark` re-enables the key.
- `./demo.sh destroy` deletes everything.

Running cost is dominated by the one interface VPC endpoint, roughly a cent an hour. Check current pricing.

## Open questions for the team

- Which AWS account should this live in? It needs a role that can create IAM, Lambda, VPC and EventBridge resources.
- Does the network lock also apply to Bedrock's own API keys (bearer tokens)? Unverified. Fallback is an SCP that blocks long-term Bedrock keys.
- Should we add a running LLM gateway (LiteLLM) so the stolen gateway key case can be shown live?
- Which leak routes show up most in real startup cases? Act 2 should lead with those.
- GuardDuty AI Protection: who can enable it, and do we show sample findings or wait for real ones?
- How should this line up with the seller one-pagers for the enablement session?
