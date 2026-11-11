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


class Verification(BaseModel):
    outcome: VerificationOutcome
    verifier: str
    risk: VerificationRisk
    reason: str = ""
    poc: Optional[PoC] = None
    cleanup_status: Optional[str] = None
