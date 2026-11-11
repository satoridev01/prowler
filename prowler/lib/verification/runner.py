import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Protocol

from prowler.lib.logger import logger
from prowler.lib.outputs.common import Status
from prowler.lib.outputs.finding import Finding
from prowler.lib.verification.models import (
    PoC,
    Verification,
    VerificationOutcome,
    VerificationRisk,
)

MAX_OUTPUT_BYTES = 16 * 1024
DEFAULT_TIMEOUT_SECONDS = 20

_SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(aws_secret_access_key\s*[=:]\s*)\S+"),
    re.compile(r"(?i)(aws_session_token\s*[=:]\s*)\S+"),
)


def _redact(value: str) -> str:
    value = value[:MAX_OUTPUT_BYTES]
    for pattern in _SECRET_PATTERNS:
        value = pattern.sub(
            lambda match: (
                f"{match.group(1)}[REDACTED]" if match.lastindex else "[REDACTED]"
            ),
            value,
        )
    return value


@dataclass(frozen=True)
class VerificationContext:
    account_id: str
    profile: str | None
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS


class VerificationAdapter(Protocol):
    name: str
    risk: VerificationRisk

    def supports(self, finding: Finding) -> bool: ...

    def verify(
        self, finding: Finding, context: VerificationContext
    ) -> Verification: ...


def _run_command(
    argv: list[str], timeout_seconds: int, *, anonymous_aws: bool = False
) -> tuple[int | None, str, str]:
    """Run an allowlisted argv without a shell and with bounded output."""
    executable = shutil.which(argv[0])
    if executable is None:
        return None, "", f"Required tool is not installed: {argv[0]}"

    env = os.environ.copy()
    if anonymous_aws:
        for key in (
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_PROFILE",
            "AWS_DEFAULT_PROFILE",
            "AWS_CONFIG_FILE",
            "AWS_SHARED_CREDENTIALS_FILE",
        ):
            env.pop(key, None)
        env["AWS_EC2_METADATA_DISABLED"] = "true"

    try:
        result = subprocess.run(
            [executable, *argv[1:]],
            capture_output=True,
            check=False,
            env=env,
            shell=False,
            text=True,
            timeout=timeout_seconds,
        )
        return result.returncode, _redact(result.stdout), _redact(result.stderr)
    except subprocess.TimeoutExpired as error:
        return None, _redact(error.stdout or ""), "Verification timed out"


class S3AnonymousListAdapter:
    """Confirm unauthenticated ListBucket access without enumerating object keys."""

    name = "aws-cli/s3-anonymous-head-bucket"
    risk = VerificationRisk.PASSIVE
    check_ids = {"s3_bucket_public_list_acl"}

    def supports(self, finding: Finding) -> bool:
        return finding.check_id in self.check_ids and bool(finding.resource_name)

    def verify(self, finding: Finding, context: VerificationContext) -> Verification:
        argv = [
            "aws",
            "s3api",
            "head-bucket",
            "--bucket",
            finding.resource_name,
            "--no-sign-request",
        ]
        exit_code, stdout, stderr = _run_command(
            argv, context.timeout_seconds, anonymous_aws=True
        )
        poc = PoC(
            tool="aws-cli",
            command=argv,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            evidence=(
                "The unauthenticated HeadBucket request succeeded; the bucket grants "
                "the public s3:ListBucket capability."
                if exit_code == 0
                else "The unauthenticated HeadBucket request did not succeed."
            ),
        )
        if exit_code == 0:
            return Verification(
                outcome=VerificationOutcome.VERIFIED,
                verifier=self.name,
                risk=self.risk,
                poc=poc,
            )
        if exit_code is None:
            return Verification(
                outcome=VerificationOutcome.ERROR,
                verifier=self.name,
                risk=self.risk,
                reason=stderr,
                poc=poc,
            )
        return Verification(
            outcome=VerificationOutcome.NOT_REPRODUCED,
            verifier=self.name,
            risk=self.risk,
            reason=(
                "Public listing was not reproduced. This does not disprove other "
                "public S3 permissions reported by Prowler."
            ),
            poc=poc,
        )


DEFAULT_ADAPTERS: tuple[VerificationAdapter, ...] = (S3AnonymousListAdapter(),)


def _allowed_accounts() -> set[str]:
    return {
        account.strip()
        for account in os.getenv("PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS", "").split(",")
        if account.strip()
    }


def verify_findings(
    findings: list[Finding],
    account_id: str,
    profile: str | None = None,
    adapters: tuple[VerificationAdapter, ...] = DEFAULT_ADAPTERS,
) -> list[Finding]:
    """Attach verification results to failed findings, failing closed by account."""
    allowed_accounts = _allowed_accounts()
    if account_id not in allowed_accounts:
        raise ValueError(
            "Dynamic verification refused: set PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS "
            f"to explicitly include target account {account_id}."
        )

    context = VerificationContext(account_id=account_id, profile=profile)
    for finding in findings:
        if finding.status != Status.FAIL or finding.muted:
            continue
        adapter = next((item for item in adapters if item.supports(finding)), None)
        if adapter is None:
            continue
        try:
            finding.verification = adapter.verify(finding, context)
        except Exception as error:
            logger.error("Verification adapter %s failed: %s", adapter.name, error)
            finding.verification = Verification(
                outcome=VerificationOutcome.ERROR,
                verifier=adapter.name,
                risk=adapter.risk,
                reason=str(error),
            )
    return findings
