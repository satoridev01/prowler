import shlex
from enum import Enum
from typing import Optional

from pydantic.v1 import BaseModel, Field


class VerificationOutcome(str, Enum):
    VERIFIED = "verified"
    NOT_REPRODUCED = "not_reproduced"
    SKIPPED = "skipped"
    ERROR = "error"


class VerificationRisk(str, Enum):
    PASSIVE = "passive"
    READ_ONLY = "read_only"
    ACTIVE = "active"


class PoC(BaseModel):
    """Reproducible proof produced by a curated verification adapter."""

    tool: str
    tool_version: Optional[str] = None
    command: list[str] = Field(default_factory=list)
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    evidence: str = ""


class Enrichment(BaseModel):
    """Extra attack-context attached to a verified finding by a tool.

    Enrichers never change the verification outcome; they add evidence (e.g. a
    nuclei web scan of a confirmed endpoint, or the IAM role a reachable host
    carries). They are best-effort: a missing tool or any error is swallowed.
    """

    tool: str
    risk: VerificationRisk = VerificationRisk.READ_ONLY
    command: list[str] = Field(default_factory=list)
    summary: str = ""
    findings: list = Field(default_factory=list)
    cleanup_status: Optional[str] = None


class Verification(BaseModel):
    outcome: VerificationOutcome
    verifier: str
    risk: VerificationRisk
    reason: str = ""
    poc: Optional[PoC] = None
    cleanup_status: Optional[str] = None
    enrichment: list[Enrichment] = Field(default_factory=list)


def verification_output(verification: Verification) -> dict:
    """Serialize for reports, with each command as one shell-escaped element.

    Consumers render ``command`` joined by spaces, so a raw argv holding a
    multi-line ``python3 -c`` script breaks when pasted into a shell.
    """
    data = verification.dict(exclude_none=True)
    for holder in [data.get("poc"), *data.get("enrichment", [])]:
        if holder and holder.get("command"):
            holder["command"] = [shlex.join(holder["command"])]
    return data
