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

The initial adapter confirms `s3_bucket_public_list_acl` with an unsigned
`HeadBucket` request. It does not enumerate keys or download objects. Its CLI,
exit code, bounded/redacted output, and evidence are stored under
`verification.poc` and exported to CSV, OCSF, and SARIF.

## Verification image

The opt-in image includes AWS CLI, CloudFox, Nuclei, Pacu, and Stratus Red Team:

```sh
docker build -t prowler-satori:local .
docker build -f Dockerfile.verify \
  --build-arg PROWLER_BASE_IMAGE=prowler-satori:local \
  -t prowler-satori:verify .
```

Only registered adapters can execute tools. Pacu and Stratus are installed for
future controlled adapters but are not invoked by the current implementation.
Any future active adapter must require a separate attacker identity, a target
account allowlist, deterministic cleanup, and a positive cleanup result in the
PoC record.
