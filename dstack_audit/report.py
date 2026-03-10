"""Generate Markdown audit report from pipeline results."""
from .models import AuditReport, Finding, Severity, Stage


def severity_icon(s: Severity) -> str:
    if s == Severity.CRITICAL:
        return "[CRITICAL]"
    elif s == Severity.WARNING:
        return "[WARNING]"
    return "[INFO]"


def generate_report(report: AuditReport) -> str:
    """Generate a Markdown audit report."""
    lines = []
    lines.append(f"# dstack-audit Report")
    lines.append("")
    lines.append(f"**Repo:** {report.repo_url}")
    lines.append(f"**Website:** {report.website_url}")
    lines.append(f"**Stage:** {report.stage.value} ({'DevProof' if report.stage == Stage.STAGE_1 else 'Ruggable'})")
    lines.append("")

    # Summary of critical findings
    critical = [f for f in report.findings if f.severity == Severity.CRITICAL]
    warnings = [f for f in report.findings if f.severity == Severity.WARNING]
    infos = [f for f in report.findings if f.severity == Severity.INFO]

    lines.append(f"## Summary")
    lines.append("")
    lines.append(f"- **Critical findings:** {len(critical)}")
    lines.append(f"- **Warnings:** {len(warnings)}")
    lines.append(f"- **Info:** {len(infos)}")
    lines.append("")

    # Phase 1: URL Parsing
    if report.parsed_url:
        p = report.parsed_url
        lines.append("## Phase 1: URL Parsing")
        lines.append("")
        lines.append(f"- App ID: `{p.app_id}`")
        lines.append(f"- Cluster: `{p.cluster}`")
        lines.append(f"- Port: {p.port}")
        lines.append(f"- TLS Passthrough: {p.tls_passthrough}")
        lines.append("")

    # Phase 2: Attestation
    if report.attestation:
        a = report.attestation
        lines.append("## Phase 2: Attestation")
        lines.append("")
        if a.error:
            lines.append(f"**Error:** {a.error}")
        else:
            lines.append(f"- App name: `{a.app_name}`")
            lines.append(f"- Compose hash: `{a.compose_hash}`")
            lines.append(f"- TDX quote present: {a.has_tdx_quote}")
            lines.append(f"- KMS enabled: {a.kms_enabled}")
            if a.allowed_envs:
                lines.append(f"- Allowed envs: `{', '.join(a.allowed_envs)}`")
            else:
                lines.append(f"- Allowed envs: (none)")

            # Show images from compose
            if a.docker_compose_file:
                images = []
                for line in a.docker_compose_file.splitlines():
                    if 'image:' in line:
                        images.append(line.strip())
                if images:
                    lines.append(f"- Docker images:")
                    for img in images:
                        lines.append(f"  - `{img}`")
        lines.append("")

    # Phase 2b: Attestation Verification
    if report.attestation:
        a = report.attestation
        qv = a.quote_verification
        dv = a.dstack_verification
        if qv or dv:
            lines.append("## Phase 2b: Attestation Verification")
            lines.append("")
            lines.append("| Check | Status |")
            lines.append("|-------|--------|")

            if qv:
                if qv.verified:
                    lines.append("| TDX quote signature valid | PASS |")
                elif qv.error:
                    lines.append(f"| TDX quote signature valid | FAIL ({qv.error}) |")
                else:
                    lines.append("| TDX quote signature valid | SKIPPED (parsed only) |")

                if qv.tcb_status:
                    lines.append(f"| TCB status | {qv.tcb_status} |")

                if qv.compose_hash_matches is True:
                    lines.append("| Compose hash matches quote | PASS |")
                elif qv.compose_hash_matches is False:
                    lines.append("| Compose hash matches quote | FAIL |")
                else:
                    lines.append("| Compose hash matches quote | N/A |")

                if qv.report_data_valid is True:
                    lines.append("| Report data binding | PASS |")
                elif qv.report_data_valid is False:
                    lines.append("| Report data binding | FAIL |")

            if dv:
                if dv.verified:
                    lines.append("| Event log replay | PASS |")
                    lines.append(f"| App component valid | {'PASS' if dv.app_valid else 'FAIL'} |")
                    lines.append(f"| KMS component valid | {'PASS' if dv.kms_valid else 'FAIL'} |")
                    lines.append(f"| Gateway component valid | {'PASS' if dv.gateway_valid else 'FAIL'} |")
                    lines.append(f"| Compose verified by service | {'PASS' if dv.compose_verified else 'FAIL'} |")
                elif dv.error:
                    lines.append(f"| Event log replay | SKIPPED ({dv.error}) |")

            # Show extracted measurements if available
            if qv and (qv.mr_config_id or qv.rtmr0):
                lines.append("")
                lines.append("**Extracted Measurements:**")
                lines.append("")
                if qv.mr_config_id:
                    lines.append(f"- mr_config_id: `{qv.mr_config_id[:32]}...`")
                if qv.mr_td:
                    lines.append(f"- mr_td: `{qv.mr_td[:32]}...`")
                if qv.rtmr0:
                    lines.append(f"- rtmr0: `{qv.rtmr0[:32]}...`")
                if qv.rtmr1:
                    lines.append(f"- rtmr1: `{qv.rtmr1[:32]}...`")
                if qv.rtmr2:
                    lines.append(f"- rtmr2: `{qv.rtmr2[:32]}...`")
                if qv.rtmr3:
                    lines.append(f"- rtmr3: `{qv.rtmr3[:32]}...`")

            lines.append("")

    # Phase 3: TLS Binding
    if report.tls:
        t = report.tls
        lines.append("## Phase 3: TLS Binding")
        lines.append("")
        if t.error:
            lines.append(f"**Error:** {t.error}")
        elif t.gateway_terminated:
            lines.append("- TLS is **gateway-terminated** (not end-to-end)")
            lines.append("- Trust assumption: Phala gateway is not compromised")
        else:
            lines.append(f"- Cert fingerprint: `{t.cert_fingerprint}`")
            if t.has_attestation_endpoint:
                lines.append(f"- Attested fingerprint: `{t.attested_fingerprint}`")
                if t.fingerprints_match:
                    lines.append("- **Match:** Certificate is bound to TEE attestation")
                else:
                    lines.append("- **MISMATCH:** Certificate does NOT match attestation")
            else:
                lines.append("- No /attestation endpoint found")
        lines.append("")

    # Phase 4: Code Analysis
    if report.code_analysis:
        c = report.code_analysis
        lines.append("## Phase 4: Code Analysis")
        lines.append("")
        if c.error:
            lines.append(f"**Error:** {c.error}")
        else:
            for category, label in [
                ('configurable_urls', 'Configurable URLs'),
                ('external_network_calls', 'External Network Calls'),
                ('attestation_code', 'Attestation Code'),
                ('red_flags', 'Red Flags'),
                ('build_reproducibility', 'Build Reproducibility'),
                ('secrets_storage', 'Secrets/Storage'),
                ('smart_contracts', 'Smart Contracts'),
            ]:
                matches = getattr(c, category, [])
                if matches:
                    lines.append(f"### {label} ({len(matches)} match{'es' if len(matches) != 1 else ''})")
                    lines.append("")
                    for m in matches[:20]:  # Cap at 20 per category
                        lines.append(f"- `{m['file']}:{m['line']}` — {m['content'][:120]}")
                    if len(matches) > 20:
                        lines.append(f"- ... and {len(matches) - 20} more")
                    lines.append("")
        lines.append("")

    # Phase 5: Cross-Reference
    if report.cross_reference:
        x = report.cross_reference
        lines.append("## Phase 5: Cross-Reference")
        lines.append("")
        if x.error:
            lines.append(f"**Error:** {x.error}")
        else:
            lines.append(f"- Compose match: {x.compose_diff_summary}")
            if x.image_issues:
                lines.append("- Image issues:")
                for issue in x.image_issues:
                    lines.append(f"  - {issue}")
            if x.env_issues:
                lines.append("- Environment issues:")
                for issue in x.env_issues:
                    lines.append(f"  - {issue}")
        lines.append("")

    # Phase 6: Stage Assessment
    if report.stage_assessment:
        s = report.stage_assessment
        lines.append("## Phase 6: Stage Assessment")
        lines.append("")
        lines.append(f"**Stage {s.stage.value}** — {'DevProof' if s.stage == Stage.STAGE_1 else 'Ruggable'}")
        lines.append("")
        if s.reasons:
            lines.append("**Reasons for current stage:**")
            for r in s.reasons:
                lines.append(f"- {r}")
            lines.append("")
        lines.append("**Stage 1 Checklist:**")
        lines.append("")
        lines.append("| Requirement | Status |")
        lines.append("|---|---|")
        labels = {
            'tdx_quote': 'TDX Hardware Quote',
            'quote_verified': 'Quote Cryptographically Verified',
            'compose_hash_verified': 'Compose Hash Matches Quote',
            'onchain_kms': 'On-chain KMS (AppAuth)',
            'pinned_images': 'Pinned Image Digests',
            'no_exfiltration_vectors': 'No Exfiltration Vectors',
            'tls_binding': 'TLS Binding Verified',
            'reproducible_builds': 'Reproducible Builds',
            'timelock': 'Upgrade Timelock',
            'appauth_contract': 'AppAuth Contract',
        }
        for key, label in labels.items():
            passed = s.stage1_checklist.get(key, False)
            icon = "PASS" if passed else "FAIL"
            lines.append(f"| {label} | {icon} |")
        lines.append("")

    # All findings
    if report.findings:
        lines.append("## All Findings")
        lines.append("")
        for f in sorted(report.findings, key=lambda x: x.severity.value):
            lines.append(f"### {severity_icon(f.severity)} {f.title}")
            lines.append("")
            lines.append(f"*Phase: {f.phase} | Category: {f.category}*")
            lines.append("")
            lines.append(f"{f.detail}")
            lines.append("")

    return '\n'.join(lines)
