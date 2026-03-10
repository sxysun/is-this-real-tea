"""Phase 6: ERC-733 stage assessment."""
from ..models import (
    AttestationResult, CodeAnalysisResult, CrossReferenceResult,
    Finding, Severity, Stage, StageAssessment, TLSResult,
)


def assess_stage(
    attestation: AttestationResult,
    tls: TLSResult,
    code: CodeAnalysisResult,
    xref: CrossReferenceResult,
    findings: list[Finding],
) -> tuple[StageAssessment, list[Finding]]:
    """Apply ERC-733 criteria to determine DevProof stage.

    Stage 0 (Ruggable) if ANY of:
      - No TDX quote (--dev-os)
      - Pha KMS without on-chain AppAuth
      - Mutable image tags
      - Configurable URLs that can exfiltrate user data
      - No AppAuth contract on Base
      - Instant upgrades (no timelock)

    Stage 1 (DevProof) requires ALL of:
      - On-chain KMS with AppAuth
      - Pinned image digests
      - Timelock on upgrades
      - No configurable exfiltration vectors
      - TLS binding verified
      - Reproducible builds
    """
    assessment = StageAssessment()
    new_findings = []

    # Build checklist
    checklist = {
        'tdx_quote': False,
        'onchain_kms': False,
        'pinned_images': True,  # Assume true, set false if issues found
        'no_exfiltration_vectors': True,
        'tls_binding': False,
        'reproducible_builds': False,
        'timelock': False,
        'appauth_contract': False,
    }

    # Check TDX quote (and cryptographic verification)
    if attestation and attestation.has_tdx_quote:
        checklist['tdx_quote'] = True

        # Factor in cryptographic verification results
        qv = attestation.quote_verification
        if qv:
            if qv.verified:
                checklist['quote_verified'] = True
            elif qv.error:
                checklist['quote_verified'] = False
                assessment.reasons.append(f"Quote verification: {qv.error}")
            else:
                # Parsed but not cryptographically verified
                checklist['quote_verified'] = False
                assessment.reasons.append(
                    "TDX quote parsed but not cryptographically verified "
                    "(dcap-qvl not available)"
                )

            if qv.compose_hash_matches is True:
                checklist['compose_hash_verified'] = True
            elif qv.compose_hash_matches is False:
                checklist['compose_hash_verified'] = False
                assessment.reasons.append(
                    "Compose hash MISMATCH: computed hash does not match "
                    "mr_config_id in TDX quote"
                )
                new_findings.append(Finding(
                    phase="stage_assessment",
                    severity=Severity.CRITICAL,
                    title="Compose hash mismatch with TDX quote",
                    detail=(
                        "The locally computed compose hash does not match the "
                        "mr_config_id embedded in the TDX quote. The deployed "
                        "configuration may differ from what was attested."
                    ),
                    category="compose_hash_mismatch",
                ))

            # TCB status check
            if qv.tcb_status and qv.tcb_status not in (
                'UpToDate', 'SWHardeningNeeded',
                'unverified (parsed manually, dcap-qvl not available)',
            ):
                new_findings.append(Finding(
                    phase="stage_assessment",
                    severity=Severity.WARNING,
                    title=f"TCB status: {qv.tcb_status}",
                    detail=(
                        f"The TCB (Trusted Computing Base) status is "
                        f"'{qv.tcb_status}'. This may indicate outdated "
                        f"firmware or known vulnerabilities in the TEE platform."
                    ),
                    category="tcb_status",
                ))
        else:
            checklist['quote_verified'] = False
            checklist['compose_hash_verified'] = False
    else:
        assessment.reasons.append("No TDX quote (likely --dev-os mode)")
        new_findings.append(Finding(
            phase="stage_assessment",
            severity=Severity.CRITICAL,
            title="No TDX quote detected",
            detail=(
                "The app appears to run without hardware attestation (--dev-os). "
                "No TEE guarantees are provided."
            ),
            category="no_tdx",
        ))
        checklist['quote_verified'] = False
        checklist['compose_hash_verified'] = False

    # Check KMS type (Pha KMS vs on-chain)
    if attestation and attestation.kms_enabled:
        # Look for on-chain AppAuth indicators in code analysis
        has_appauth = False
        if code:
            for m in code.smart_contracts:
                if any(kw in m.get('content', '').lower()
                       for kw in ['appauth', 'composehash', 'addcomposehash']):
                    has_appauth = True
                    break
        if has_appauth:
            checklist['onchain_kms'] = True
            checklist['appauth_contract'] = True
        else:
            assessment.reasons.append("KMS enabled but no on-chain AppAuth found")
    else:
        assessment.reasons.append("KMS not enabled")

    # Check image pinning
    critical_categories = {'mutable_image', 'variable_image'}
    for f in findings:
        if f.category in critical_categories:
            checklist['pinned_images'] = False
            if 'mutable_image' not in [r for r in assessment.reasons]:
                assessment.reasons.append("Mutable or variable image tags detected")
            break

    # Check exfiltration vectors
    exfil_categories = {'configurable_url'}
    for f in findings:
        if f.category in exfil_categories:
            checklist['no_exfiltration_vectors'] = False
            assessment.reasons.append(
                f"Configurable exfiltration vector: {f.title}"
            )
            break

    # Check configurable URLs from code analysis
    if code and code.configurable_urls:
        for m in code.configurable_urls:
            content = m.get('content', '')
            # Check if it's in compose/env context
            if any(kw in content.lower() for kw in ['url', 'endpoint', 'base']):
                checklist['no_exfiltration_vectors'] = False
                if not any('configurable' in r.lower() for r in assessment.reasons):
                    assessment.reasons.append("Configurable URLs found in code")
                break

    # Check TLS binding
    if tls:
        if tls.gateway_terminated:
            assessment.reasons.append("Gateway-terminated TLS (not end-to-end)")
        elif tls.fingerprints_match:
            checklist['tls_binding'] = True
        elif tls.fingerprints_match is False:
            assessment.reasons.append("TLS fingerprint mismatch")
            new_findings.append(Finding(
                phase="stage_assessment",
                severity=Severity.CRITICAL,
                title="TLS certificate fingerprint mismatch",
                detail=(
                    "The TLS certificate fingerprint does not match the attested "
                    "fingerprint. This could indicate a MITM attack."
                ),
                category="tls_mismatch",
            ))

    # Check reproducible builds
    if code and code.build_reproducibility:
        has_epoch = any('SOURCE_DATE_EPOCH' in m.get('content', '')
                        for m in code.build_reproducibility)
        has_pinned = checklist['pinned_images']
        if has_epoch and has_pinned:
            checklist['reproducible_builds'] = True

    # Determine stage
    stage0_reasons = []
    if not checklist['tdx_quote']:
        stage0_reasons.append("No TDX quote")
    if not checklist['pinned_images']:
        stage0_reasons.append("Mutable image tags")
    if not checklist['no_exfiltration_vectors']:
        stage0_reasons.append("Configurable exfiltration vectors")
    if not checklist['onchain_kms']:
        stage0_reasons.append("No on-chain KMS/AppAuth")

    if stage0_reasons:
        assessment.stage = Stage.STAGE_0
    else:
        # Check all Stage 1 requirements
        all_stage1 = all(checklist.values())
        if all_stage1:
            assessment.stage = Stage.STAGE_1
        else:
            assessment.stage = Stage.STAGE_0
            missing = [k for k, v in checklist.items() if not v]
            assessment.reasons.append(
                f"Missing Stage 1 requirements: {', '.join(missing)}"
            )

    assessment.stage1_checklist = checklist
    return assessment, new_findings
