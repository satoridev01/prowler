from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from prowler.lib.verification.models import VerificationOutcome
from prowler.lib.verification.runner import _run_command, verify_findings
from tests.lib.outputs.fixtures.fixtures import generate_finding_output


def test_verification_fails_closed_without_account_allowlist(monkeypatch):
    monkeypatch.delenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", raising=False)

    with pytest.raises(ValueError, match="explicitly include target account"):
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
