# Dynamic finding verification

This fork adds an opt-in `--verify` phase after Prowler creates its normalized
findings. Verification is deliberately separate from detection: a failed
reproduction does not turn a Prowler failure into a pass.

## Safety boundary

`--verify` fails closed unless the audited AWS account is explicitly present in
`PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS`. This allows the Satori worker to audit an
AWSGoat account without permitting dynamic checks against the Satori account.

```sh
export PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS=959479862535
prowler aws --profile satori-scout --verify
```

Never point `PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS` at a production account.

## Adapters

Each adapter reproduces the finding from the outside, without credentials, and
records the exact command, exit code, bounded/redacted output and evidence under
`verification.poc` (exported to CSV, OCSF and SARIF). Nothing is written to the
target and request bodies are never sent.

| Checks | Proof | Risk |
|---|---|---|
| `s3_bucket_public_list_acl` | unsigned `aws s3api head-bucket` | passive |
| `s3_bucket_public_access` | unsigned `aws s3api head-object` on one key (metadata only). The key comes from an anonymous `list-objects-v2`, or from the scan's own read-only credentials when listing is not public | read_only |
| `ec2_instance_port_*_exposed_to_internet`, `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_*` | TCP connect to the public IP(s) and read the service banner | passive |
| `apigateway_restapi_authorizers_enabled`, `apigateway_restapi_public` | unauthenticated `GET` to a deployed method whose authorization is `NONE`. Methods other than GET are never called | passive |
| `elbv2_ssl_listeners` | `GET` over plain HTTP to each listener that does not redirect | passive |

Outcomes: `verified`, `not_reproduced` (the probe ran and failed; this does not
turn the finding into a pass), `skipped` (nothing safe to probe, e.g. no public
IP) and `error`. Findings without an adapter get no `verification` block. A
summary line `Dynamic verification (<account>): verified=N, ...` is printed to
stdout after the scan.

## Active adapter (pacu)

One adapter is not read-only: `PacuPrivescAdapter`, for
`iam_policy_allows_privilege_escalation` and
`iam_inline_policy_allows_privilege_escalation`. It attaches the flagged
policy to a disposable test IAM user, runs pacu's `iam__privesc_scan
--scan-only` against it (detection only — `--scan-only` is what stops pacu
from attempting the methods it finds, not just reporting them), then detaches
the policy in a `finally` and re-verifies the detach with a fresh
`ListAttachedUserPolicies` call. A failed detach is recorded in
`cleanup_status` and logged, never swallowed.

It is inert unless all four of these are set (on top of the account
allowlist):

```sh
export PROWLER_VERIFY_ACTIVE=1
export PROWLER_VERIFY_ACTIVE_OPERATOR_PROFILE=awsgoat   # can attach/detach policies
export PROWLER_VERIFY_ACTIVE_TARGET_PROFILE=awsgoat-attacker  # pacu runs as this
export PROWLER_VERIFY_ACTIVE_TARGET_USER=awsgoat-attacker
```

Use a disposable test principal for the target, never a real one: during the
scan it briefly holds whatever the flagged policy grants, which for an
`Action: "*"` policy is full admin on the account for the few seconds the
scan takes.

## Verification image

The opt-in image includes AWS CLI, CloudFox, Nuclei, Pacu, and Stratus Red Team:

```sh
docker build -t prowler-satori:local .
docker build -f Dockerfile.verify \
  --build-arg PROWLER_BASE_IMAGE=prowler-satori:local \
  -t prowler-satori:verify .
```

Only registered adapters can execute tools. Pacu is wired as the one active
adapter above; Stratus is installed for future controlled adapters but is not
invoked by the current implementation. Any future active adapter must require
a separate attacker identity, a target account allowlist, deterministic
cleanup, and a positive cleanup result in the PoC record.
