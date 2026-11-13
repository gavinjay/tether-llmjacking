# Policies

Both files work as an IAM policy on one identity or as a service control policy (SCP) across an organization.
As an SCP the account cannot remove them, which closes the "stolen key detaches the lock" gap.

- `block-long-term-bedrock-keys.json`: denies creating and using long-term Bedrock API keys, using the condition keys
  AWS added in September 2025. Statements 1 and 2 are taken from the Bedrock user guide. Not yet tested by us.
- `network-lock-template.json`: the Tether network lock. Replace the endpoint ID. Test on one identity before
  applying it broadly: anything that calls Bedrock from outside that endpoint, including people in the console, is denied.
