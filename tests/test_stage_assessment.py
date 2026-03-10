"""Tests for Phase 6: Stage assessment."""
import pytest
from dstack_audit.models import (
    AttestationResult, CodeAnalysisResult, CrossReferenceResult,
    Finding, Severity, Stage, TLSResult,
)
from dstack_audit.phases.stage_assessment import assess_stage


def make_attestation(**kwargs) -> AttestationResult:
    defaults = dict(
        has_tdx_quote=True,
        kms_enabled=True,
        allowed_envs=[],
        docker_compose_file="image: app@sha256:" + "a" * 64,
    )
    defaults.update(kwargs)
    return AttestationResult(**defaults)


def make_tls(**kwargs) -> TLSResult:
    return TLSResult(**kwargs)


def make_code(**kwargs) -> CodeAnalysisResult:
    return CodeAnalysisResult(**kwargs)


def make_xref(**kwargs) -> CrossReferenceResult:
    return CrossReferenceResult(**kwargs)


class TestStageAssessment:
    def test_no_tdx_quote_is_stage_0(self):
        stage, _ = assess_stage(
            attestation=make_attestation(has_tdx_quote=False),
            tls=make_tls(),
            code=make_code(),
            xref=make_xref(),
            findings=[],
        )
        assert stage.stage == Stage.STAGE_0
        assert any('TDX' in r or 'quote' in r.lower() for r in stage.reasons)

    def test_mutable_images_is_stage_0(self):
        findings = [Finding(
            phase="cross_reference",
            severity=Severity.CRITICAL,
            title="Mutable image tag",
            detail="test",
            category="mutable_image",
        )]
        stage, _ = assess_stage(
            attestation=make_attestation(),
            tls=make_tls(),
            code=make_code(),
            xref=make_xref(),
            findings=findings,
        )
        assert stage.stage == Stage.STAGE_0
        assert stage.stage1_checklist['pinned_images'] is False

    def test_configurable_url_is_stage_0(self):
        findings = [Finding(
            phase="cross_reference",
            severity=Severity.CRITICAL,
            title="Configurable URL: LLM_BASE_URL",
            detail="test",
            category="configurable_url",
        )]
        stage, _ = assess_stage(
            attestation=make_attestation(),
            tls=make_tls(),
            code=make_code(),
            xref=make_xref(),
            findings=findings,
        )
        assert stage.stage == Stage.STAGE_0
        assert stage.stage1_checklist['no_exfiltration_vectors'] is False

    def test_no_kms_is_stage_0(self):
        stage, _ = assess_stage(
            attestation=make_attestation(kms_enabled=False),
            tls=make_tls(),
            code=make_code(),
            xref=make_xref(),
            findings=[],
        )
        assert stage.stage == Stage.STAGE_0
        assert stage.stage1_checklist['onchain_kms'] is False

    def test_gateway_tls_noted(self):
        stage, _ = assess_stage(
            attestation=make_attestation(),
            tls=make_tls(gateway_terminated=True),
            code=make_code(),
            xref=make_xref(),
            findings=[],
        )
        assert any('gateway' in r.lower() for r in stage.reasons)

    def test_tls_fingerprint_match_passes(self):
        stage, _ = assess_stage(
            attestation=make_attestation(),
            tls=make_tls(fingerprints_match=True),
            code=make_code(smart_contracts=[
                {'content': 'AppAuth addComposeHash', 'file': 'x', 'line': '1'}
            ]),
            xref=make_xref(),
            findings=[],
        )
        assert stage.stage1_checklist['tls_binding'] is True

    def test_checklist_keys_present(self):
        stage, _ = assess_stage(
            attestation=make_attestation(),
            tls=make_tls(),
            code=make_code(),
            xref=make_xref(),
            findings=[],
        )
        expected_keys = {
            'tdx_quote', 'quote_verified', 'compose_hash_verified',
            'onchain_kms', 'pinned_images',
            'no_exfiltration_vectors', 'tls_binding',
            'reproducible_builds', 'timelock', 'appauth_contract',
        }
        assert set(stage.stage1_checklist.keys()) == expected_keys
