from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import pytest

from prowler.lib.verification.models import VerificationOutcome, VerificationRisk
from prowler.lib.verification.runner import (
    CloudFoxInstanceRoleEnricher,
    PacuPrivescAdapter,
    _run_command,
    verify_findings,
)
from tests.lib.outputs.fixtures.fixtures import generate_finding_output


def test_verification_fails_closed_without_account_allowlist(monkeypatch):
    monkeypatch.delenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", raising=False)

    with pytest.raises(ValueError, match="explicitly include the audited account"):
        verify_findings([], account_id="123456789012")


def test_verification_ignores_unsupported_findings(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    finding = generate_finding_output(
        status="FAIL", check_id="service_unsupported_check"
    )

    assert verify_findings([finding], account_id="123456789012")[0].verification is None


def test_s3_anonymous_list_verification(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    finding = generate_finding_output(
        status="FAIL",
        check_id="s3_bucket_public_list_acl",
        service_name="s3",
        resource_name="public-test-bucket",
    )

    with patch(
        "prowler.lib.verification.runner._run_command",
        return_value=(0, "", ""),
    ) as command:
        result = verify_findings([finding], account_id="123456789012")[0]

    assert result.verification.outcome == VerificationOutcome.VERIFIED
    assert result.verification.poc.command == [
        "aws",
        "s3api",
        "head-bucket",
        "--bucket",
        "public-test-bucket",
        "--no-sign-request",
    ]
    command.assert_called_once()


def test_pass_findings_are_not_verified(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    finding = generate_finding_output(
        status="PASS",
        check_id="s3_bucket_public_list_acl",
        service_name="s3",
        resource_name="public-test-bucket",
    )

    assert verify_findings([finding], account_id="123456789012")[0].verification is None


def test_anonymous_aws_command_cannot_inherit_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA0000000000000000")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/tmp/credentials")

    with (
        patch("prowler.lib.verification.runner.shutil.which", return_value="/aws"),
        patch(
            "prowler.lib.verification.runner.subprocess.run",
            return_value=CompletedProcess(["/aws"], 0, "", ""),
        ) as run,
    ):
        _run_command(["aws", "sts", "get-caller-identity"], 1, anonymous_aws=True)

    environment = run.call_args.kwargs["env"]
    assert "AWS_ACCESS_KEY_ID" not in environment
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert "AWS_SHARED_CREDENTIALS_FILE" not in environment
    assert environment["AWS_EC2_METADATA_DISABLED"] == "true"
    assert run.call_args.kwargs["shell"] is False


def _fail(check_id, metadata, **kwargs):
    kwargs.setdefault("service_name", check_id.split("_")[0])
    finding = generate_finding_output(status="FAIL", check_id=check_id, **kwargs)
    finding.resource_metadata = metadata
    return finding


def test_ssh_exposure_probes_public_ip(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ENRICH", "0")
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    finding = _fail(
        "ec2_instance_port_ssh_exposed_to_internet", {"public_ip": "203.0.113.10"}
    )

    with patch(
        "prowler.lib.verification.runner._run_command",
        return_value=(0, "connected to 203.0.113.10:22\nbanner: SSH-2.0-OpenSSH", ""),
    ) as command:
        result = verify_findings([finding], account_id="123456789012")[0]

    assert result.verification.outcome == VerificationOutcome.VERIFIED
    assert result.verification.poc.command[-2:] == ["203.0.113.10", "22"]
    assert command.call_args.kwargs["anonymous_aws"] is True


def test_security_group_ports_come_from_check_name(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    finding = _fail(
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mongodb_27017_27018",
        {"network_interfaces": [{"public_ip_addresses": ["203.0.113.11"]}]},
    )

    with patch(
        "prowler.lib.verification.runner._run_command",
        return_value=(1, "connect failed", ""),
    ) as command:
        result = verify_findings([finding], account_id="123456789012")[0]

    assert result.verification.outcome == VerificationOutcome.NOT_REPRODUCED
    assert [call.args[0][-1] for call in command.call_args_list] == ["27017", "27018"]


def test_port_exposure_without_public_ip_is_skipped(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    finding = _fail("ec2_instance_port_ssh_exposed_to_internet", {})

    with patch("prowler.lib.verification.runner._run_command") as command:
        result = verify_findings([finding], account_id="123456789012")[0]

    assert result.verification.outcome == VerificationOutcome.SKIPPED
    command.assert_not_called()


def test_api_gateway_only_calls_unauthenticated_get(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ENRICH", "0")
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    finding = _fail(
        "apigateway_restapi_authorizers_enabled",
        {
            "id": "abc123",
            "region": "us-east-1",
            "public_endpoint": True,
            "stages": [{"name": "v1"}],
            "resources": [
                {"path": "/login", "resource_methods": {"POST": "NONE"}},
                {"path": "/users/{id}", "resource_methods": {"GET": "NONE"}},
                {"path": "/private", "resource_methods": {"GET": "AWS_IAM"}},
                {"path": "/dump", "resource_methods": {"GET": "NONE"}},
            ],
        },
    )

    with patch(
        "prowler.lib.verification.runner._run_command",
        return_value=(0, "HTTP 200\nGET ...", ""),
    ) as command:
        result = verify_findings([finding], account_id="123456789012")[0]

    assert result.verification.outcome == VerificationOutcome.VERIFIED
    command.assert_called_once()
    assert (
        command.call_args.args[0][-1]
        == "https://abc123.execute-api.us-east-1.amazonaws.com/v1/dump"
    )


def test_api_gateway_without_safe_method_is_skipped(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    finding = _fail(
        "apigateway_restapi_public",
        {
            "id": "abc123",
            "stages": [{"name": "v1"}],
            "resources": [{"path": "/login", "resource_methods": {"POST": "NONE"}}],
        },
    )

    with patch("prowler.lib.verification.runner._run_command") as command:
        result = verify_findings([finding], account_id="123456789012")[0]

    assert result.verification.outcome == VerificationOutcome.SKIPPED
    command.assert_not_called()


def test_api_gateway_rejection_is_not_reproduced(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    finding = _fail(
        "apigateway_restapi_public",
        {
            "id": "abc123",
            "stages": [{"name": "v1"}],
            "resources": [{"path": "/", "resource_methods": {"GET": "NONE"}}],
        },
    )

    with patch(
        "prowler.lib.verification.runner._run_command",
        return_value=(0, "HTTP 403\n", ""),
    ):
        result = verify_findings([finding], account_id="123456789012")[0]

    assert result.verification.outcome == VerificationOutcome.NOT_REPRODUCED


def test_elbv2_cleartext_listener(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ENRICH", "0")
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    listeners = {
        "l1": {"port": 80, "protocol": "HTTP", "rules": [{"actions": [{"Type": "forward"}]}]},
        "l2": {"port": 8080, "protocol": "HTTP", "rules": [{"actions": [{"Type": "redirect"}]}]},
    }
    finding = _fail(
        "elbv2_ssl_listeners",
        {"dns": "alb.example.com", "scheme": "internet-facing", "listeners": listeners},
    )

    with patch(
        "prowler.lib.verification.runner._run_command",
        return_value=(0, "HTTP 200\n", ""),
    ) as command:
        result = verify_findings([finding], account_id="123456789012")[0]

    assert result.verification.outcome == VerificationOutcome.VERIFIED
    command.assert_called_once()
    assert command.call_args.args[0][-1] == "http://alb.example.com:80/"


def test_s3_public_read_uses_unsigned_head_object(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    finding = _fail(
        "s3_bucket_public_access",
        {"region": "us-east-1"},
        service_name="s3",
        resource_name="public-bucket",
    )

    with patch(
        "prowler.lib.verification.runner._run_command",
        side_effect=[(0, "index.html\n", ""), (0, "{}", "")],
    ) as command:
        result = verify_findings([finding], account_id="123456789012")[0]

    assert result.verification.outcome == VerificationOutcome.VERIFIED
    assert result.verification.risk == VerificationRisk.PASSIVE
    head_object = command.call_args_list[1].args[0]
    assert head_object[:3] == ["aws", "s3api", "head-object"]
    assert "--no-sign-request" in head_object and "index.html" in head_object
    assert all(call.kwargs["anonymous_aws"] for call in command.call_args_list)


def test_s3_public_read_falls_back_to_scan_credentials_for_listing(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    finding = _fail(
        "s3_bucket_public_access",
        {"region": "us-east-1"},
        service_name="s3",
        resource_name="read-only-bucket",
    )
    session = MagicMock()
    session.client.return_value.list_objects_v2.return_value = {
        "Contents": [{"Key": "build/app.js"}]
    }

    with patch(
        "prowler.lib.verification.runner._run_command",
        side_effect=[(254, "", "AccessDenied"), (0, "{}", "")],
    ):
        result = verify_findings(
            [finding], account_id="123456789012", session=session
        )[0]

    assert result.verification.outcome == VerificationOutcome.VERIFIED
    assert "build/app.js" in result.verification.poc.command
    assert "read-only credentials" in result.verification.poc.evidence
    assert result.verification.risk == VerificationRisk.PASSIVE


def test_verified_http_finding_is_enriched_with_nuclei(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    finding = _fail(
        "apigateway_restapi_public",
        {
            "id": "abc123",
            "region": "us-east-1",
            "stages": [{"name": "v1"}],
            "resources": [{"path": "/dump", "resource_methods": {"GET": "NONE"}}],
        },
    )
    nuclei_matches = [
        {"template": "apache-detect", "severity": "info", "name": "Apache", "matched_at": "x"},
        {"template": "exposed-sqli", "severity": "high", "name": "SQLi", "matched_at": "x"},
    ]

    with (
        patch(
            "prowler.lib.verification.runner._run_command",
            return_value=(0, "HTTP 200\n", ""),
        ),
        patch(
            "prowler.lib.verification.runner._nuclei_scan",
            return_value=(nuclei_matches, ["nuclei", "-u", "x"]),
        ),
        patch(
            "prowler.lib.verification.runner.CloudFoxInstanceRoleEnricher.applies_to",
            return_value=False,
        ),
    ):
        result = verify_findings([finding], account_id="123456789012")[0]

    assert result.verification.outcome == VerificationOutcome.VERIFIED
    assert len(result.verification.enrichment) == 1
    enr = result.verification.enrichment[0]
    assert enr.tool == "nuclei"
    assert "1 above info" in enr.summary
    assert len(enr.findings) == 2


def test_enrichment_can_be_disabled(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    monkeypatch.setenv("PROWLER_VERIFY_ENRICH", "0")
    finding = _fail(
        "apigateway_restapi_public",
        {
            "id": "abc123",
            "stages": [{"name": "v1"}],
            "resources": [{"path": "/dump", "resource_methods": {"GET": "NONE"}}],
        },
    )
    with (
        patch(
            "prowler.lib.verification.runner._run_command",
            return_value=(0, "HTTP 200\n", ""),
        ),
        patch("prowler.lib.verification.runner._nuclei_scan") as nuclei,
    ):
        result = verify_findings([finding], account_id="123456789012")[0]

    assert result.verification.outcome == VerificationOutcome.VERIFIED
    assert result.verification.enrichment == []
    nuclei.assert_not_called()


def test_enricher_errors_do_not_break_verification(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    finding = _fail(
        "apigateway_restapi_public",
        {
            "id": "abc123",
            "stages": [{"name": "v1"}],
            "resources": [{"path": "/dump", "resource_methods": {"GET": "NONE"}}],
        },
    )
    with (
        patch(
            "prowler.lib.verification.runner._run_command",
            return_value=(0, "HTTP 200\n", ""),
        ),
        patch(
            "prowler.lib.verification.runner._nuclei_scan",
            side_effect=RuntimeError("boom"),
        ),
    ):
        result = verify_findings([finding], account_id="123456789012")[0]

    assert result.verification.outcome == VerificationOutcome.VERIFIED
    assert result.verification.enrichment == []


def test_cloudfox_enriches_open_port_with_instance_role(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    finding = _fail(
        "ec2_instance_port_ssh_exposed_to_internet", {"public_ip": "203.0.113.10"}
    )

    def fake_run(argv, timeout, anonymous_aws=False):
        if argv[0] == "python3":  # the TCP probe
            return (0, "connected to 203.0.113.10:22\nbanner: SSH", "")
        return (0, "", "")

    with (
        patch("prowler.lib.verification.runner._run_command", side_effect=fake_run),
        patch("prowler.lib.verification.runner.shutil.which", return_value="/cloudfox"),
        patch.object(
            CloudFoxInstanceRoleEnricher,
            "_instances",
            return_value={
                "203.0.113.10": {
                    "ID": "i-0abc",
                    "Role": "AWS_GOAT_ROLE",
                    "CanPrivEscToAdmin?": "YES",
                }
            },
        ),
    ):
        result = verify_findings([finding], account_id="123456789012")[0]

    assert result.verification.outcome == VerificationOutcome.VERIFIED
    enrichment = result.verification.enrichment[0]
    assert enrichment.tool == "cloudfox"
    assert enrichment.findings[0]["role"] == "AWS_GOAT_ROLE"
    assert enrichment.findings[0]["can_privesc_to_admin"] is True
    assert "privilege-escalation path" in enrichment.summary


def test_cloudfox_uses_the_external_ip_field_name(monkeypatch):
    """cloudfox's own JSON column is "External IP" (with a space), not ExternalIP."""
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    finding = _fail(
        "ec2_instance_port_ssh_exposed_to_internet", {"public_ip": "203.0.113.10"}
    )

    def fake_run(argv, timeout, anonymous_aws=False):
        if argv[0] == "python3":
            return (0, "connected to 203.0.113.10:22\nbanner: SSH", "")
        return (0, "", "")

    import json
    import tempfile

    outdir = tempfile.mkdtemp()
    instances_dir = f"{outdir}/json"
    import os

    os.makedirs(instances_dir)
    with open(f"{instances_dir}/instances.json", "w") as f:
        json.dump(
            [{"ID": "i-0abc", "Role": "AWS_GOAT_ROLE", "External IP": "203.0.113.10"}], f
        )

    import prowler.lib.verification.runner as runner_module

    runner_module._cloudfox_instances_cache = None  # the module caches this per process
    with (
        patch("prowler.lib.verification.runner._run_command", side_effect=fake_run),
        patch("prowler.lib.verification.runner.shutil.which", return_value="/cloudfox"),
        patch("tempfile.mkdtemp", return_value=outdir),
    ):
        result = verify_findings([finding], account_id="123456789012")[0]

    assert result.verification.enrichment[0].findings[0]["role"] == "AWS_GOAT_ROLE"


def _active_env(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ACTIVE", "1")
    monkeypatch.setenv("PROWLER_VERIFY_ACTIVE_OPERATOR_PROFILE", "awsgoat-deployer")
    monkeypatch.setenv("PROWLER_VERIFY_ACTIVE_TARGET_PROFILE", "awsgoat-privesc-test-user")
    monkeypatch.setenv("PROWLER_VERIFY_ACTIVE_TARGET_USER", "awsgoat-privesc-test-user")


def test_pacu_adapter_is_inert_without_full_opt_in(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    monkeypatch.setenv("PROWLER_VERIFY_ENRICH", "0")
    monkeypatch.delenv("PROWLER_VERIFY_ACTIVE", raising=False)
    finding = _fail(
        "iam_policy_allows_privilege_escalation",
        {},
        resource_uid="arn:aws:iam::123456789012:policy/some-policy",
    )

    assert PacuPrivescAdapter().supports(finding) is False

    with patch("prowler.lib.verification.runner._run_privileged") as privileged:
        result = verify_findings([finding], account_id="123456789012")[0]

    assert result.verification is None
    privileged.assert_not_called()


def test_pacu_adapter_skips_when_policy_already_attached(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    monkeypatch.setenv("PROWLER_VERIFY_ENRICH", "0")
    _active_env(monkeypatch)
    policy_arn = "arn:aws:iam::123456789012:policy/ec2DeployerAdmin-policy"
    finding = _fail(
        "iam_policy_allows_privilege_escalation", {}, resource_uid=policy_arn
    )

    with patch(
        "prowler.lib.verification.runner._run_privileged",
        return_value=(0, f'{{"AttachedPolicies": [{{"PolicyArn": "{policy_arn}"}}]}}', ""),
    ) as privileged:
        result = verify_findings([finding], account_id="123456789012")[0]

    assert result.verification.outcome == VerificationOutcome.SKIPPED
    assert "already attached" in result.verification.reason
    privileged.assert_called_once()  # only the baseline read; never attach/detach


def test_pacu_adapter_verified_and_cleaned_up(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    monkeypatch.setenv("PROWLER_VERIFY_ENRICH", "0")
    _active_env(monkeypatch)
    policy_arn = "arn:aws:iam::123456789012:policy/ec2DeployerAdmin-policy"
    finding = _fail(
        "iam_policy_allows_privilege_escalation", {}, resource_uid=policy_arn
    )
    calls = []

    def fake_run(argv, timeout):
        calls.append(argv)
        if argv[:3] == ["aws", "iam", "list-attached-user-policies"]:
            return (0, '{"AttachedPolicies": []}', "")
        if argv[:3] == ["aws", "iam", "attach-user-policy"]:
            return (0, "", "")
        if argv[:3] == ["aws", "iam", "detach-user-policy"]:
            return (0, "", "")
        if "iam__privesc_scan" in argv:
            return (0, "  CONFIRMED: CreateNewPolicyVersion\n", "")
        return (0, "", "")  # new-session / import-keys / set-regions / enum_permissions

    with patch(
        "prowler.lib.verification.runner._run_privileged", side_effect=fake_run
    ):
        result = verify_findings([finding], account_id="123456789012")[0]

    assert result.verification.outcome == VerificationOutcome.VERIFIED
    assert result.verification.cleanup_status == "verified"
    assert "CreateNewPolicyVersion" in result.verification.poc.evidence
    # attach must happen before detach, and both must be present
    kinds = [c[2] for c in calls if c[:2] == ["aws", "iam"]]
    assert kinds.index("attach-user-policy") < kinds.index("detach-user-policy")


def test_pacu_adapter_records_cleanup_failure_without_swallowing_it(monkeypatch, caplog):
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    monkeypatch.setenv("PROWLER_VERIFY_ENRICH", "0")
    _active_env(monkeypatch)
    policy_arn = "arn:aws:iam::123456789012:policy/ec2DeployerAdmin-policy"
    finding = _fail(
        "iam_policy_allows_privilege_escalation", {}, resource_uid=policy_arn
    )

    def fake_run(argv, timeout):
        if argv[:3] == ["aws", "iam", "list-attached-user-policies"]:
            return (0, '{"AttachedPolicies": []}', "")
        if argv[:3] == ["aws", "iam", "attach-user-policy"]:
            return (0, "", "")
        if argv[:3] == ["aws", "iam", "detach-user-policy"]:
            return (1, "", "AccessDenied")  # cleanup fails
        if "iam__privesc_scan" in argv:
            return (0, "  None found\n", "")
        return (0, "", "")

    with patch(
        "prowler.lib.verification.runner._run_privileged", side_effect=fake_run
    ):
        result = verify_findings([finding], account_id="123456789012")[0]

    assert result.verification.cleanup_status.startswith("FAILED")
    assert any("cleanup FAILED" in record.message for record in caplog.records)


def test_pacu_adapter_detaches_even_if_the_scan_step_raises(monkeypatch):
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    monkeypatch.setenv("PROWLER_VERIFY_ENRICH", "0")
    _active_env(monkeypatch)
    policy_arn = "arn:aws:iam::123456789012:policy/ec2DeployerAdmin-policy"
    finding = _fail(
        "iam_policy_allows_privilege_escalation", {}, resource_uid=policy_arn
    )
    detach_calls = []

    def fake_run(argv, timeout):
        if argv[:3] == ["aws", "iam", "list-attached-user-policies"]:
            return (0, '{"AttachedPolicies": []}', "")
        if argv[:3] == ["aws", "iam", "attach-user-policy"]:
            return (0, "", "")
        if argv[:3] == ["aws", "iam", "detach-user-policy"]:
            detach_calls.append(argv)
            return (0, "", "")
        if "iam__privesc_scan" in argv:
            raise RuntimeError("pacu crashed")
        return (0, "", "")

    with patch(
        "prowler.lib.verification.runner._run_privileged", side_effect=fake_run
    ):
        result = verify_findings([finding], account_id="123456789012")[0]

    assert len(detach_calls) == 1  # cleanup still ran despite the crash
    assert result.verification.outcome == VerificationOutcome.ERROR


def test_pacu_adapter_never_sends_scan_only_minus_flag(monkeypatch):
    """--scan-only must always be present: it is what stops pacu from
    attempting the escalation methods it finds, not just reporting them."""
    monkeypatch.setenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "123456789012")
    monkeypatch.setenv("PROWLER_VERIFY_ENRICH", "0")
    _active_env(monkeypatch)
    policy_arn = "arn:aws:iam::123456789012:policy/ec2DeployerAdmin-policy"
    finding = _fail(
        "iam_policy_allows_privilege_escalation", {}, resource_uid=policy_arn
    )
    scan_argvs = []

    def fake_run(argv, timeout):
        if argv[:3] == ["aws", "iam", "list-attached-user-policies"]:
            return (0, '{"AttachedPolicies": []}', "")
        if "iam__privesc_scan" in argv:
            scan_argvs.append(argv)
            return (0, "  None found\n", "")
        return (0, "", "")

    with patch(
        "prowler.lib.verification.runner._run_privileged", side_effect=fake_run
    ):
        verify_findings([finding], account_id="123456789012")

    assert scan_argvs and "--module-args=--scan-only" in scan_argvs[0]


def test_pacu_adapter_isolates_ambient_aws_credentials(monkeypatch):
    """The operator's --profile must win; ambient scan credentials must not
    leak into the attach/detach/pacu subprocess environment."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA0000000000000000")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")

    with (
        patch("prowler.lib.verification.runner.shutil.which", return_value="/aws"),
        patch(
            "prowler.lib.verification.runner.subprocess.run",
            return_value=CompletedProcess(["/aws"], 0, "{}", ""),
        ) as run,
    ):
        from prowler.lib.verification.runner import _run_privileged

        _run_privileged(["aws", "iam", "list-attached-user-policies"], 10)

    environment = run.call_args.kwargs["env"]
    assert "AWS_ACCESS_KEY_ID" not in environment
    assert "AWS_SECRET_ACCESS_KEY" not in environment
