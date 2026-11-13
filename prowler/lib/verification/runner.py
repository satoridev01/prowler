import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Protocol

from prowler.lib.logger import logger
from prowler.lib.outputs.common import Status
from prowler.lib.outputs.finding import Finding
from prowler.lib.verification.models import (
    Enrichment,
    PoC,
    Verification,
    VerificationOutcome,
    VerificationRisk,
)

MAX_OUTPUT_BYTES = 16 * 1024
DEFAULT_TIMEOUT_SECONDS = 20
MAX_TARGETS_PER_FINDING = 3

_SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(aws_secret_access_key\s*[=:]\s*)\S+"),
    re.compile(r"(?i)(aws_session_token\s*[=:]\s*)\S+"),
)

# Probes run as `python3 -c <probe> <args>` so the PoC records the exact,
# reproducible command. They only use the standard library and never carry
# AWS credentials (see `anonymous_aws`).
TCP_PROBE = """import socket,sys
host,port=sys.argv[1],int(sys.argv[2])
try:
    s=socket.create_connection((host,port),timeout=5)
except OSError as e:
    print(f"connect {host}:{port} failed: {e}");sys.exit(1)
print(f"connected to {host}:{port}")
s.settimeout(3)
try:
    banner=s.recv(256).decode("latin-1").strip()
except OSError:
    banner=""
print(f"banner: {banner}" if banner else "banner: (none sent)")
s.close()
"""

HTTP_PROBE = """import sys,urllib.request,urllib.error
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*a,**k):return None
url=sys.argv[1]
try:
    r=urllib.request.build_opener(NoRedirect).open(urllib.request.Request(url,headers={"User-Agent":"prowler-verify"}),timeout=10)
except urllib.error.HTTPError as e:
    r=e
except Exception as e:
    print(f"GET {url} failed: {e}");sys.exit(1)
print(f"HTTP {r.status if hasattr(r,'status') else r.code}")
print(f"GET {url}")
for h in ("Server","Content-Type","Location"):
    if r.headers.get(h):print(f"{h}: {r.headers.get(h)}")
print()
print(r.read(512).decode("utf-8","replace"))
"""

# Ports probed for each exposure check. Security group checks encode their
# ports in the check name (tcp_port_..._3306); instance checks do not.
INSTANCE_PORT_CHECKS = {
    "ec2_instance_port_cassandra_exposed_to_internet": (7199, 9160, 8888),
    "ec2_instance_port_cifs_exposed_to_internet": (139, 445),
    "ec2_instance_port_elasticsearch_kibana_exposed_to_internet": (9200, 9300, 5601),
    "ec2_instance_port_ftp_exposed_to_internet": (21, 20),
    "ec2_instance_port_kafka_exposed_to_internet": (9092,),
    "ec2_instance_port_kerberos_exposed_to_internet": (88, 464, 749, 750),
    "ec2_instance_port_ldap_exposed_to_internet": (389, 636),
    "ec2_instance_port_memcached_exposed_to_internet": (11211,),
    "ec2_instance_port_mongodb_exposed_to_internet": (27017, 27018),
    "ec2_instance_port_mysql_exposed_to_internet": (3306,),
    "ec2_instance_port_oracle_exposed_to_internet": (1521, 2483, 2484),
    "ec2_instance_port_postgresql_exposed_to_internet": (5432,),
    "ec2_instance_port_rdp_exposed_to_internet": (3389,),
    "ec2_instance_port_redis_exposed_to_internet": (6379,),
    "ec2_instance_port_sqlserver_exposed_to_internet": (1433, 1434),
    "ec2_instance_port_ssh_exposed_to_internet": (22,),
    "ec2_instance_port_telnet_exposed_to_internet": (23,),
}
SECURITY_GROUP_PORT_PREFIX = "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_"


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
    session: Any = None

    def boto3_session(self):
        """The scan's own (read-only) session, used only for discovery."""
        if self.session is not None:
            return self.session
        import boto3

        if self.profile and self.profile != "default":
            return boto3.Session(profile_name=self.profile)
        return boto3.Session()


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
        partial = error.stdout or ""
        if isinstance(partial, bytes):  # TimeoutExpired keeps bytes even with text=True
            partial = partial.decode("utf-8", "replace")
        return None, _redact(partial), "Verification timed out"


def _probe(argv: list[str], timeout_seconds: int) -> tuple[int | None, str, str]:
    """Run a network probe with no AWS credentials in its environment."""
    return _run_command(argv, timeout_seconds, anonymous_aws=True)


def _http_status(stdout: str) -> int | None:
    match = re.match(r"HTTP (\d{3})", stdout)
    return int(match.group(1)) if match else None


def _result(
    adapter,
    outcome: VerificationOutcome,
    poc: PoC | None = None,
    reason: str = "",
) -> Verification:
    return Verification(
        outcome=outcome, verifier=adapter.name, risk=adapter.risk, reason=reason, poc=poc
    )


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
            return _result(self, VerificationOutcome.VERIFIED, poc)
        if exit_code is None:
            return _result(self, VerificationOutcome.ERROR, poc, stderr)
        return _result(
            self,
            VerificationOutcome.NOT_REPRODUCED,
            poc,
            "Public listing was not reproduced. This does not disprove other "
            "public S3 permissions reported by Prowler.",
        )


class S3AnonymousReadAdapter:
    """Confirm that an object can be read without credentials.

    Picks one key with an anonymous ListObjectsV2; if listing is not public,
    picks it with the scan's own read-only credentials. The proof is always an
    unsigned HeadObject: object metadata only, the body is never downloaded.
    """

    name = "aws-cli/s3-anonymous-head-object"
    risk = VerificationRisk.READ_ONLY
    check_ids = {"s3_bucket_public_access"}

    def supports(self, finding: Finding) -> bool:
        return finding.check_id in self.check_ids and bool(finding.resource_name)

    def verify(self, finding: Finding, context: VerificationContext) -> Verification:
        bucket = finding.resource_name
        region = (finding.resource_metadata or {}).get("region") or finding.region
        listed_by = "anonymous ListObjectsV2"
        list_argv = [
            "aws", "s3api", "list-objects-v2", "--bucket", bucket,
            "--max-keys", "1", "--query", "Contents[0].Key", "--output", "text",
            "--region", region, "--no-sign-request",
        ]
        exit_code, stdout, _ = _run_command(
            list_argv, context.timeout_seconds, anonymous_aws=True
        )
        key = stdout.strip() if exit_code == 0 else ""
        if key in ("", "None"):
            listed_by = "the scan's read-only credentials"
            try:
                response = context.boto3_session().client(
                    "s3", region_name=region
                ).list_objects_v2(Bucket=bucket, MaxKeys=1)
                key = (response.get("Contents") or [{}])[0].get("Key", "")
            except Exception as error:
                return _result(
                    self, VerificationOutcome.ERROR,
                    reason=f"Could not pick an object to test: {error}",
                )
        if not key:
            return _result(
                self, VerificationOutcome.SKIPPED,
                reason="The bucket is empty; there is no object to read.",
            )

        argv = [
            "aws", "s3api", "head-object", "--bucket", bucket, "--key", key,
            "--region", region, "--no-sign-request",
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
                f"Object s3://{bucket}/{key} (picked with {listed_by}) is readable "
                "by an unauthenticated request."
                if exit_code == 0
                else f"Unauthenticated HeadObject on s3://{bucket}/{key} was denied."
            ),
        )
        if exit_code == 0:
            return _result(self, VerificationOutcome.VERIFIED, poc)
        if exit_code is None:
            return _result(self, VerificationOutcome.ERROR, poc, stderr)
        return _result(
            self, VerificationOutcome.NOT_REPRODUCED, poc,
            "The tested object was not publicly readable; other objects or "
            "actions may still be public.",
        )


class NetworkPortExposureAdapter:
    """Confirm that a port flagged as open to the internet accepts connections."""

    name = "python/tcp-connect"
    risk = VerificationRisk.PASSIVE

    @staticmethod
    def _ports(check_id: str) -> tuple[int, ...]:
        if check_id in INSTANCE_PORT_CHECKS:
            return INSTANCE_PORT_CHECKS[check_id]
        if check_id.startswith(SECURITY_GROUP_PORT_PREFIX):
            return tuple(
                int(port) for port in re.findall(r"\d+", check_id[len(SECURITY_GROUP_PORT_PREFIX):])
            )
        return ()

    @staticmethod
    def _public_ips(finding: Finding) -> list[str]:
        # In-process metadata holds model values (IPv4Address, ENI id strings),
        # not the JSON-serialized form seen in the OCSF output.
        metadata = finding.resource_metadata or {}
        ips = [metadata.get("public_ip")]
        for interface in metadata.get("network_interfaces") or []:
            if not isinstance(interface, dict):
                interface = getattr(interface, "__dict__", {})
            ips.extend(interface.get("public_ip_addresses") or [])
            ips.append((interface.get("association") or {}).get("PublicIp"))
        return list(dict.fromkeys(str(ip) for ip in ips if ip))

    def supports(self, finding: Finding) -> bool:
        return bool(self._ports(finding.check_id))

    def verify(self, finding: Finding, context: VerificationContext) -> Verification:
        ips = self._public_ips(finding)[:MAX_TARGETS_PER_FINDING]
        if not ips:
            return _result(
                self, VerificationOutcome.SKIPPED,
                reason="No public IP is attached to this resource.",
            )
        poc = None
        for ip in ips:
            for port in self._ports(finding.check_id):
                argv = ["python3", "-c", TCP_PROBE, ip, str(port)]
                exit_code, stdout, stderr = _probe(argv, context.timeout_seconds)
                poc = PoC(
                    tool="python3 socket",
                    command=argv,
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr,
                    evidence=(
                        f"TCP {ip}:{port} accepted a connection from the internet."
                        if exit_code == 0
                        else f"TCP {ip}:{port} did not accept a connection."
                    ),
                )
                if exit_code == 0:
                    return _result(self, VerificationOutcome.VERIFIED, poc)
        return _result(
            self, VerificationOutcome.NOT_REPRODUCED, poc,
            "No probed port accepted a connection (the service may be stopped or "
            "filtered elsewhere, e.g. by a network ACL).",
        )


class ApiGatewayUnauthenticatedAdapter:
    """Confirm that a REST API answers a request that carries no credentials.

    Only GET methods whose authorization type is NONE and whose path has no
    parameters are called. POST/PUT/DELETE are never sent.
    """

    name = "python/http-get-unauthenticated"
    risk = VerificationRisk.PASSIVE
    check_ids = {"apigateway_restapi_authorizers_enabled", "apigateway_restapi_public"}

    def supports(self, finding: Finding) -> bool:
        return finding.check_id in self.check_ids

    def verify(self, finding: Finding, context: VerificationContext) -> Verification:
        metadata = finding.resource_metadata or {}
        if metadata.get("public_endpoint") is False:
            return _result(
                self, VerificationOutcome.SKIPPED,
                reason="The API endpoint is private.",
            )
        api_id = metadata.get("id")
        region = metadata.get("region") or finding.region
        stages = [stage.get("name") for stage in metadata.get("stages") or [] if stage.get("name")]
        paths = sorted(
            (
                resource["path"]
                for resource in metadata.get("resources") or []
                if "{" not in resource.get("path", "")
                and (resource.get("resource_methods") or {}).get("GET") == "NONE"
            ),
            key=len,
        )
        if not (api_id and stages and paths):
            return _result(
                self, VerificationOutcome.SKIPPED,
                reason="No deployed GET method without authorization to call; "
                "other methods are not sent because they may change data.",
            )
        poc = None
        targets = [(stage, path) for stage in stages for path in paths]
        for stage, path in targets[:MAX_TARGETS_PER_FINDING]:
            url = f"https://{api_id}.execute-api.{region}.amazonaws.com/{stage}{path}"
            argv = ["python3", "-c", HTTP_PROBE, url]
            exit_code, stdout, stderr = _probe(argv, context.timeout_seconds)
            status = _http_status(stdout)
            reached = status is not None and status < 500 and status not in (401, 403)
            poc = PoC(
                tool="python3 urllib",
                command=argv,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                evidence=(
                    f"GET {url} without credentials returned HTTP {status}."
                    if status
                    else f"GET {url} failed."
                ),
            )
            if reached:
                return _result(self, VerificationOutcome.VERIFIED, poc)
        return _result(
            self, VerificationOutcome.NOT_REPRODUCED, poc,
            "The unauthenticated requests were rejected or failed.",
        )


class Elbv2CleartextHttpAdapter:
    """Confirm that a load balancer serves content over plain HTTP."""

    name = "python/http-get-cleartext"
    risk = VerificationRisk.PASSIVE
    check_ids = {"elbv2_ssl_listeners"}

    def supports(self, finding: Finding) -> bool:
        return finding.check_id in self.check_ids

    def verify(self, finding: Finding, context: VerificationContext) -> Verification:
        metadata = finding.resource_metadata or {}
        dns = metadata.get("dns")
        ports = []
        for listener in (metadata.get("listeners") or {}).values():
            actions = [
                action.get("Type")
                for rule in listener.get("rules") or []
                for action in rule.get("actions") or []
            ]
            if listener.get("protocol") == "HTTP" and "redirect" not in actions:
                ports.append(listener.get("port"))
        if metadata.get("scheme") == "internal" or not dns or not ports:
            return _result(
                self, VerificationOutcome.SKIPPED,
                reason="No internet-facing plain HTTP listener to call.",
            )
        poc = None
        for port in ports[:MAX_TARGETS_PER_FINDING]:
            url = f"http://{dns}:{port}/"
            argv = ["python3", "-c", HTTP_PROBE, url]
            exit_code, stdout, stderr = _probe(argv, context.timeout_seconds)
            status = _http_status(stdout)
            redirects_to_https = bool(
                status and 300 <= status < 400 and "Location: https://" in stdout
            )
            poc = PoC(
                tool="python3 urllib",
                command=argv,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                evidence=(
                    f"{url} answered HTTP {status} in cleartext."
                    if status
                    else f"GET {url} failed."
                ),
            )
            if status and not redirects_to_https:
                return _result(self, VerificationOutcome.VERIFIED, poc)
        return _result(
            self, VerificationOutcome.NOT_REPRODUCED, poc,
            "No listener served content over plain HTTP.",
        )


DEFAULT_ADAPTERS: tuple[VerificationAdapter, ...] = (
    S3AnonymousListAdapter(),
    S3AnonymousReadAdapter(),
    NetworkPortExposureAdapter(),
    ApiGatewayUnauthenticatedAdapter(),
    Elbv2CleartextHttpAdapter(),
)


# ---------------------------------------------------------------------------
# Enrichers: best-effort attack-context attached to an already-verified finding.
# They never change the outcome and swallow every error (missing tool included).
# ---------------------------------------------------------------------------

NUCLEI_TEMPLATES_ZIP = (
    "https://codeload.github.com/projectdiscovery/nuclei-templates/zip/refs/heads/main"
)
# Template groups kept from the zip: tech fingerprinting, exposed files/panels and
# misconfigurations. Enough to turn "endpoint reachable" into "what is on it".
NUCLEI_TEMPLATE_GROUPS = ("/http/technologies/", "/http/exposures/", "/http/misconfiguration/")
NUCLEI_MAX_TARGETS = 3
_nuclei_templates_dir: str | None = None
_nuclei_unavailable = False
_cloudfox_instances_cache: dict | None = None


def _url_in_poc(verification: Verification) -> str | None:
    if not verification.poc:
        return None
    for token in reversed(verification.poc.command):
        if token.startswith("http://") or token.startswith("https://"):
            return token
    return None


def _ensure_nuclei_templates() -> str | None:
    """Download a subset of nuclei-templates once per process."""
    global _nuclei_templates_dir, _nuclei_unavailable
    if _nuclei_templates_dir or _nuclei_unavailable:
        return _nuclei_templates_dir
    if shutil.which("nuclei") is None:
        _nuclei_unavailable = True
        return None
    import io
    import tempfile
    import urllib.request
    import zipfile

    try:
        data = urllib.request.urlopen(NUCLEI_TEMPLATES_ZIP, timeout=120).read()
        archive = zipfile.ZipFile(io.BytesIO(data))
        members = [
            name
            for name in archive.namelist()
            if name.endswith(".yaml") and any(g in name for g in NUCLEI_TEMPLATE_GROUPS)
        ]
        root = tempfile.mkdtemp(prefix="nuclei-templates-")
        for name in members:
            archive.extract(name, root)
        inner = next(
            (os.path.join(root, d) for d in os.listdir(root) if d.startswith("nuclei-templates")),
            root,
        )
        _nuclei_templates_dir = os.path.join(inner, "http")
        logger.info(f"nuclei templates ready ({len(members)} templates)")
    except Exception as error:
        logger.error(f"Could not prepare nuclei templates: {error}")
        _nuclei_unavailable = True
    return _nuclei_templates_dir


def _nuclei_scan(url: str, timeout_seconds: int) -> tuple[list[dict], list[str]]:
    import json as _json

    templates = _ensure_nuclei_templates()
    if not templates:
        return [], []
    argv = [
        "nuclei", "-u", url,
        "-t", os.path.join(templates, "technologies"),
        "-t", os.path.join(templates, "exposures"),
        "-t", os.path.join(templates, "misconfiguration"),
        "-timeout", "8", "-retries", "1", "-rate-limit", "25",
        "-ni", "-duc", "-silent", "-jsonl", "-no-color",
    ]
    _, stdout, _ = _run_command(argv, timeout_seconds, anonymous_aws=True)
    matches = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            record = _json.loads(line)
        except ValueError:
            continue
        info = record.get("info") or {}
        matches.append(
            {
                "template": record.get("template-id"),
                "severity": info.get("severity"),
                "name": info.get("name"),
                "matched_at": record.get("matched-at"),
            }
        )
    return matches, argv


class Enricher(Protocol):
    def applies_to(self, finding: Finding, verification: Verification) -> bool: ...

    def enrich(
        self, finding: Finding, verification: Verification, context: VerificationContext
    ) -> Enrichment | None: ...


class NucleiWebEnricher:
    """Scan a confirmed public HTTP(S) endpoint with nuclei (read-only)."""

    def applies_to(self, finding: Finding, verification: Verification) -> bool:
        return _url_in_poc(verification) is not None

    def enrich(self, finding, verification, context):
        url = _url_in_poc(verification)
        if not url:
            return None
        matches, argv = _nuclei_scan(url, max(context.timeout_seconds, 120))
        if not argv:
            return None
        notable = [m for m in matches if m["severity"] not in (None, "info", "unknown")]
        summary = (
            f"nuclei matched {len(matches)} template(s) on {url}"
            + (f", {len(notable)} above info" if notable else " (all informational)")
        )
        return Enrichment(
            tool="nuclei", risk=VerificationRisk.READ_ONLY, command=argv,
            summary=summary, findings=matches[:50],
        )


class CloudFoxInstanceRoleEnricher:
    """Attach the IAM role a reachable EC2 host carries (attack-path context)."""

    def applies_to(self, finding: Finding, verification: Verification) -> bool:
        return finding.check_id in INSTANCE_PORT_CHECKS or finding.check_id.startswith(
            SECURITY_GROUP_PORT_PREFIX
        )

    def _instances(self, context: VerificationContext) -> dict:
        global _cloudfox_instances_cache
        if _cloudfox_instances_cache is not None:
            return _cloudfox_instances_cache
        _cloudfox_instances_cache = {}
        if shutil.which("cloudfox") is None:
            return _cloudfox_instances_cache
        import json as _json
        import tempfile

        outdir = tempfile.mkdtemp(prefix="cloudfox-")
        argv = [
            "cloudfox", "aws", "instances", "-y", "--skip-admin-check",
            "--outdir", outdir, "-v", "1",
        ]
        _run_command(argv, max(context.timeout_seconds, 180))  # uses scan credentials
        try:
            path = next(
                os.path.join(dirpath, f)
                for dirpath, _, files in os.walk(outdir)
                for f in files
                if f == "instances.json"
            )
            for row in _json.load(open(path)):
                ip = row.get("External IP") or row.get("ExternalIP") or row.get("PublicIP")
                if ip and ip not in ("", "No External IP"):
                    _cloudfox_instances_cache[str(ip)] = row
        except (StopIteration, ValueError, OSError):
            pass
        return _cloudfox_instances_cache

    def enrich(self, finding, verification, context):
        url_or_ip = _url_in_poc(verification) or ""
        ips = NetworkPortExposureAdapter._public_ips(finding)
        probed = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", " ".join(verification.poc.command)) if verification.poc else []
        candidates = probed or ips
        instances = self._instances(context)
        for ip in candidates:
            row = instances.get(str(ip))
            if not row:
                continue
            role = row.get("Role") or row.get("InstanceProfile") or "unknown"
            privesc = str(row.get("CanPrivEscToAdmin?", "")).lower() in ("yes", "true")
            is_admin = str(row.get("IsAdminRole?", "")).lower() in ("yes", "true")
            tail = (
                " cloudfox flags a privilege-escalation path from this role to admin."
                if privesc
                else " this role already has administrative access." if is_admin else ""
            )
            return Enrichment(
                tool="cloudfox", risk=VerificationRisk.READ_ONLY,
                command=["cloudfox", "aws", "instances"],
                summary=(
                    f"Reachable host {row.get('ID') or ip} carries IAM role {role}; "
                    "its credentials are retrievable from instance metadata, a "
                    "privilege-escalation entry point." + tail
                ),
                findings=[{
                    "ip": str(ip), "instance": row.get("ID"), "role": role,
                    "can_privesc_to_admin": privesc, "is_admin_role": is_admin,
                }],
            )
        return None


DEFAULT_ENRICHERS: tuple[Enricher, ...] = (
    NucleiWebEnricher(),
    CloudFoxInstanceRoleEnricher(),
)


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
    session: Any = None,
    enrichers: tuple[Enricher, ...] = DEFAULT_ENRICHERS,
) -> list[Finding]:
    """Attach verification results to failed findings, failing closed by account."""
    allowed_accounts = _allowed_accounts()
    if account_id not in allowed_accounts:
        raise ValueError(
            "Dynamic verification refused: set PROWLER_VERIFY_ALLOWED_ACCOUNT_IDS "
            f"to explicitly include target account {account_id}."
        )

    enrich_enabled = os.getenv("PROWLER_VERIFY_ENRICH", "1") not in ("0", "false", "no")
    context = VerificationContext(account_id=account_id, profile=profile, session=session)
    counts: dict[str, int] = {}
    enriched = 0
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
        outcome = finding.verification.outcome.value
        counts[outcome] = counts.get(outcome, 0) + 1
        if enrich_enabled and finding.verification.outcome == VerificationOutcome.VERIFIED:
            for enricher in enrichers:
                try:
                    if not enricher.applies_to(finding, finding.verification):
                        continue
                    extra = enricher.enrich(finding, finding.verification, context)
                    if extra:
                        finding.verification.enrichment.append(extra)
                        enriched += 1
                except Exception as error:
                    logger.error("Enricher failed on %s: %s", finding.check_id, error)
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    tail = f"; {enriched} enriched" if enriched else ""
    print(f"Dynamic verification ({account_id}): {summary or 'no supported FAIL findings'}{tail}")
    return findings
