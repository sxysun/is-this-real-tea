"""Data models for dstack-audit pipeline."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class Stage(Enum):
    STAGE_0 = 0  # Ruggable
    STAGE_1 = 1  # DevProof


@dataclass
class Finding:
    phase: str
    severity: Severity
    title: str
    detail: str
    category: str = ""


@dataclass
class ParsedURL:
    app_id: str
    cluster: str
    port: int
    tls_passthrough: bool  # True if port suffix ends with 's'
    original_url: str = ""


@dataclass
class QuoteVerification:
    verified: bool = False
    tcb_status: Optional[str] = None
    mr_config_id: Optional[str] = None
    mr_td: Optional[str] = None
    rtmr0: Optional[str] = None
    rtmr1: Optional[str] = None
    rtmr2: Optional[str] = None
    rtmr3: Optional[str] = None
    report_data: Optional[str] = None
    compose_hash_matches: Optional[bool] = None
    report_data_valid: Optional[bool] = None
    report_data_details: Optional[dict] = None
    error: Optional[str] = None


@dataclass
class DstackVerification:
    verified: bool = False
    app_valid: bool = False
    kms_valid: bool = False
    gateway_valid: bool = False
    compose_verified: bool = False
    error: Optional[str] = None


@dataclass
class AttestationResult:
    app_compose: Optional[dict] = None
    compose_hash: Optional[str] = None
    has_tdx_quote: bool = False
    quote_hex: Optional[str] = None
    kms_enabled: bool = False
    allowed_envs: list = field(default_factory=list)
    docker_compose_file: str = ""
    pre_launch_script: str = ""
    app_name: str = ""
    raw_html: str = ""
    error: Optional[str] = None
    quote_verification: Optional[QuoteVerification] = None
    dstack_verification: Optional[DstackVerification] = None
    cloud_api_data: Optional[dict] = None


@dataclass
class TLSResult:
    cert_fingerprint: Optional[str] = None
    attested_fingerprint: Optional[str] = None
    fingerprints_match: Optional[bool] = None
    gateway_terminated: bool = False
    has_attestation_endpoint: bool = False
    error: Optional[str] = None


@dataclass
class CodeAnalysisResult:
    configurable_urls: list = field(default_factory=list)
    external_network_calls: list = field(default_factory=list)
    attestation_code: list = field(default_factory=list)
    red_flags: list = field(default_factory=list)
    build_reproducibility: list = field(default_factory=list)
    secrets_storage: list = field(default_factory=list)
    smart_contracts: list = field(default_factory=list)
    repo_path: Optional[str] = None
    error: Optional[str] = None


@dataclass
class CrossReferenceResult:
    compose_match: Optional[bool] = None
    compose_diff_summary: str = ""
    image_issues: list = field(default_factory=list)
    env_issues: list = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class StageAssessment:
    stage: Stage = Stage.STAGE_0
    reasons: list = field(default_factory=list)
    stage1_checklist: dict = field(default_factory=dict)


@dataclass
class AuditReport:
    repo_url: str = ""
    website_url: str = ""
    parsed_url: Optional[ParsedURL] = None
    attestation: Optional[AttestationResult] = None
    tls: Optional[TLSResult] = None
    code_analysis: Optional[CodeAnalysisResult] = None
    cross_reference: Optional[CrossReferenceResult] = None
    stage_assessment: Optional[StageAssessment] = None
    findings: list = field(default_factory=list)
    stage: Stage = Stage.STAGE_0
