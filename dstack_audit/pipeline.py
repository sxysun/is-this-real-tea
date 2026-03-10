"""Orchestrate the 6-phase audit pipeline."""
import shutil
import sys
import tempfile

from .models import AuditReport, Finding, Severity, Stage
from .phases.url_parser import parse_phala_url, get_info_url
from .phases.attestation import (
    fetch_attestation,
    fetch_cloud_api_full,
    parse_tdx_quote_manual,
    verify_compose_hash_against_quote,
    verify_quote_dcap,
    verify_report_data_binding,
    verify_with_dstack_service,
)
from .phases.tls_binding import verify_tls_binding
from .phases.code_analysis import analyze_code, clone_repo
from .phases.cross_reference import cross_reference
from .phases.stage_assessment import assess_stage


def run_audit(repo_url: str, website_url: str, verbose: bool = False) -> AuditReport:
    """Run the full 6-phase audit pipeline.

    Args:
        repo_url: GitHub repository URL
        website_url: The app's public Phala Cloud URL
        verbose: Print progress to stderr
    """
    report = AuditReport(repo_url=repo_url, website_url=website_url)
    all_findings: list[Finding] = []

    def log(msg: str):
        if verbose:
            print(msg, file=sys.stderr)

    # Phase 1: URL Parsing
    log("Phase 1: Parsing URL...")
    try:
        parsed = parse_phala_url(website_url)
        report.parsed_url = parsed
        log(f"  App ID: {parsed.app_id}")
        log(f"  Cluster: {parsed.cluster}")
    except ValueError as e:
        log(f"  Error: {e}")
        all_findings.append(Finding(
            phase="url_parser",
            severity=Severity.CRITICAL,
            title="Cannot parse Phala URL",
            detail=str(e),
            category="url_parse_error",
        ))
        report.findings = all_findings
        return report

    # Phase 2: Attestation
    log("Phase 2: Fetching attestation...")
    info_url = get_info_url(parsed)
    attestation = fetch_attestation(info_url)
    report.attestation = attestation
    if attestation.error:
        log(f"  Error: {attestation.error}")
        all_findings.append(Finding(
            phase="attestation",
            severity=Severity.CRITICAL,
            title="Attestation fetch failed",
            detail=attestation.error,
            category="attestation_error",
        ))
    else:
        log(f"  App: {attestation.app_name}")
        log(f"  TDX quote: {attestation.has_tdx_quote}")

    # Fetch full attestation data from Cloud API if we have an app_id
    if parsed:
        log("  Fetching Cloud API attestation data...")
        cloud_data = fetch_cloud_api_full(parsed.app_id)
        if cloud_data:
            attestation.cloud_api_data = cloud_data
            # Use Cloud API quote if we don't have one from 8090
            if not attestation.quote_hex and cloud_data.get('app_quote'):
                attestation.quote_hex = cloud_data['app_quote']
                attestation.has_tdx_quote = bool(attestation.quote_hex)
                log("  Got TDX quote from Cloud API")

    # Phase 2b: Verify attestation cryptographically
    if attestation.quote_hex:
        log("Phase 2b: Verifying attestation cryptographically...")

        # Try dcap-qvl first (full cryptographic verification)
        qv = verify_quote_dcap(attestation.quote_hex)
        if qv.error and 'not installed' in qv.error:
            # Fall back to manual parsing (extracts fields but no signature check)
            log(f"  dcap-qvl not available, falling back to manual parsing")
            qv = parse_tdx_quote_manual(attestation.quote_hex)

        attestation.quote_verification = qv

        if qv.error:
            log(f"  Quote verification: {qv.error}")
        else:
            log(f"  Quote verified: {qv.verified}")
            log(f"  TCB status: {qv.tcb_status}")

            # Compare compose hash against mr_config_id
            if attestation.compose_hash:
                qv.compose_hash_matches = verify_compose_hash_against_quote(
                    attestation.compose_hash, qv
                )
                log(f"  Compose hash matches quote: {qv.compose_hash_matches}")

            # Verify report_data binding if we have the data
            if qv.report_data:
                rd_result = verify_report_data_binding(qv.report_data)
                qv.report_data_valid = rd_result.get('valid', False)
                qv.report_data_details = rd_result
                log(f"  Report data first 32 bytes: {rd_result.get('report_data_first_32', 'N/A')[:16]}...")

        # Try dstack-verifier service for event log replay
        cloud = attestation.cloud_api_data or {}
        event_log = cloud.get('app_event_log', '')
        vm_config = cloud.get('app_vm_config', '')
        if event_log or vm_config:
            log("  Trying dstack-verifier service for event log replay...")
            dv = verify_with_dstack_service(
                attestation.quote_hex, event_log, vm_config, attestation.app_compose
            )
            attestation.dstack_verification = dv
            if dv.error:
                log(f"  dstack-verifier: {dv.error}")
            else:
                log(f"  dstack-verifier: verified={dv.verified}")
    else:
        log("  No TDX quote available, skipping cryptographic verification")

    # Phase 3: TLS Binding
    log("Phase 3: Verifying TLS binding...")
    tls = verify_tls_binding(website_url, parsed.tls_passthrough)
    report.tls = tls
    if tls.error:
        log(f"  Error: {tls.error}")
    elif tls.gateway_terminated:
        log("  Gateway-terminated TLS")
    elif tls.fingerprints_match is not None:
        log(f"  Fingerprints match: {tls.fingerprints_match}")

    # Phase 4: Code Analysis
    log("Phase 4: Analyzing source code...")
    repo_path = None
    try:
        repo_path = tempfile.mkdtemp(prefix='dstack-audit-')
        clone_repo(repo_url, repo_path)
        code = analyze_code(repo_path)
        report.code_analysis = code
        total = sum(
            len(getattr(code, cat, []))
            for cat in ['configurable_urls', 'external_network_calls',
                        'attestation_code', 'red_flags', 'build_reproducibility',
                        'secrets_storage', 'smart_contracts']
        )
        log(f"  Found {total} code matches across 7 categories")
    except Exception as e:
        log(f"  Error: {e}")
        from .models import CodeAnalysisResult
        code = CodeAnalysisResult(error=str(e))
        report.code_analysis = code

    # Phase 5: Cross-Reference
    log("Phase 5: Cross-referencing deployed vs source...")
    if attestation.docker_compose_file and repo_path:
        xref, xref_findings = cross_reference(
            deployed_compose=attestation.docker_compose_file,
            allowed_envs=attestation.allowed_envs,
            repo_path=repo_path,
        )
        report.cross_reference = xref
        all_findings.extend(xref_findings)
        log(f"  Image issues: {len(xref.image_issues)}")
        log(f"  Env issues: {len(xref.env_issues)}")
    else:
        from .models import CrossReferenceResult
        report.cross_reference = CrossReferenceResult(
            error="No deployed compose or repo available"
        )

    # Cleanup cloned repo
    if repo_path:
        try:
            shutil.rmtree(repo_path)
        except Exception:
            pass

    # Phase 6: Stage Assessment
    log("Phase 6: Assessing DevProof stage...")
    from .models import CrossReferenceResult
    stage, stage_findings = assess_stage(
        attestation=attestation,
        tls=tls,
        code=code,
        xref=report.cross_reference or CrossReferenceResult(),
        findings=all_findings,
    )
    report.stage_assessment = stage
    all_findings.extend(stage_findings)
    report.stage = stage.stage
    log(f"  Stage: {stage.stage.value}")

    report.findings = all_findings
    return report
