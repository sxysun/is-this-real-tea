"""Tests for Phase 2b: Attestation verification functions."""
import json
import struct
import pytest
from unittest.mock import patch, MagicMock

from dstack_audit.models import QuoteVerification, DstackVerification
from dstack_audit.phases.attestation import (
    verify_quote_dcap,
    parse_tdx_quote_manual,
    verify_compose_hash_against_quote,
    verify_report_data_binding,
    verify_with_dstack_service,
    compute_compose_hash,
)


def make_fake_tdx_quote_hex(
    mr_config_id: bytes = b'\x00' * 48,
    mr_td: bytes = b'\x00' * 48,
    rtmr0: bytes = b'\x00' * 48,
    rtmr1: bytes = b'\x00' * 48,
    rtmr2: bytes = b'\x00' * 48,
    rtmr3: bytes = b'\x00' * 48,
    report_data: bytes = b'\x00' * 64,
) -> str:
    """Build a minimal fake TDX Quote v4 byte string for testing manual parsing.

    Must match the offsets used in parse_tdx_quote_manual():
      Header: 48 bytes
      TD Report offsets (from td_offset=48):
        +80: mr_td (48 bytes)
        +128: mr_config_id (48 bytes)
        +272: rtmr0 (48 bytes)
        +320: rtmr1 (48 bytes)
        +368: rtmr2 (48 bytes)
        +416: rtmr3 (48 bytes)
        +464: report_data (64 bytes)
    """
    # Header: version=4 (2B LE), att_key_type=2 (2B), tee_type=0x81 (4B), rest zeros
    header = struct.pack('<HHI', 4, 2, 0x81) + b'\x00' * 40  # 48 bytes total

    # Build TD report as a bytearray so we can place fields at exact offsets
    td_report = bytearray(528)  # 464 + 64 = 528 bytes minimum

    # Place fields at their offsets within td_report
    td_report[80:128] = mr_td
    td_report[128:176] = mr_config_id
    td_report[272:320] = rtmr0
    td_report[320:368] = rtmr1
    td_report[368:416] = rtmr2
    td_report[416:464] = rtmr3
    td_report[464:528] = report_data

    quote_bytes = header + bytes(td_report)
    # Pad to make it look realistic
    quote_bytes += b'\x00' * max(0, 700 - len(quote_bytes))

    return '0x' + quote_bytes.hex()


class TestParseQuoteManual:
    def test_parse_basic_quote(self):
        """Manual parsing extracts fields at correct offsets."""
        mr_config = b'\x01' + bytes.fromhex('aa' * 32) + b'\x00' * 15
        mr_td_val = bytes.fromhex('bb' * 48)
        rtmr0_val = bytes.fromhex('cc' * 48)
        report_data_val = bytes.fromhex('dd' * 32 + 'ee' * 32)

        quote_hex = make_fake_tdx_quote_hex(
            mr_config_id=mr_config,
            mr_td=mr_td_val,
            rtmr0=rtmr0_val,
            report_data=report_data_val,
        )

        qv = parse_tdx_quote_manual(quote_hex)
        assert qv.error is None
        assert qv.verified is False  # Manual parse doesn't verify
        assert qv.mr_config_id.startswith('01')
        assert 'aa' * 32 in qv.mr_config_id
        assert qv.mr_td == 'bb' * 48
        assert qv.rtmr0 == 'cc' * 48
        assert qv.report_data[:64] == 'dd' * 32

    def test_parse_short_quote(self):
        """Too-short quotes return error."""
        qv = parse_tdx_quote_manual('0xaabb')
        assert qv.error is not None
        assert 'too short' in qv.error.lower()

    def test_parse_invalid_hex(self):
        qv = parse_tdx_quote_manual('0xNOTHEX')
        assert qv.error is not None

    def test_parse_with_0x_prefix(self):
        quote_hex = make_fake_tdx_quote_hex()
        qv1 = parse_tdx_quote_manual(quote_hex)
        qv2 = parse_tdx_quote_manual(quote_hex[2:])  # without 0x
        assert qv1.mr_config_id == qv2.mr_config_id

    def test_parse_wrong_version(self):
        # Build a quote with version=99
        header = struct.pack('<HHI', 99, 2, 0x81) + b'\x00' * 40
        body = b'\x00' * 700
        quote_hex = (header + body).hex()
        qv = parse_tdx_quote_manual(quote_hex)
        assert qv.error is not None
        assert 'version' in qv.error.lower()


class TestVerifyComposeHash:
    def test_matching_hash(self):
        compose = {"name": "test", "version": 1}
        h = compute_compose_hash(compose)
        qv = QuoteVerification(
            mr_config_id='01' + h + '0' * 30,  # 01 + 64 hex + padding
        )
        assert verify_compose_hash_against_quote(h, qv) is True

    def test_mismatched_hash(self):
        qv = QuoteVerification(
            mr_config_id='01' + 'ff' * 32 + '0' * 30,
        )
        assert verify_compose_hash_against_quote('aa' * 32, qv) is False

    def test_no_config_id(self):
        qv = QuoteVerification(mr_config_id='')
        assert verify_compose_hash_against_quote('aa' * 32, qv) is False

    def test_wrong_prefix(self):
        """mr_config_id not starting with '01' returns False."""
        qv = QuoteVerification(
            mr_config_id='02' + 'aa' * 32 + '0' * 30,
        )
        assert verify_compose_hash_against_quote('aa' * 32, qv) is False


class TestVerifyReportData:
    def test_no_checks(self):
        """With no address or nonce, just parses report_data."""
        rd = 'aa' * 32 + 'bb' * 32
        result = verify_report_data_binding(rd)
        assert result['valid'] is True
        assert result['report_data_first_32'] == 'aa' * 32
        assert result['report_data_last_32'] == 'bb' * 32

    def test_address_match(self):
        addr = 'deadbeef' + '00' * 28
        nonce = 'cafebabe' + '00' * 28
        rd = addr + nonce
        result = verify_report_data_binding(rd, signing_address='0xdeadbeef')
        assert result['address_matches'] is True
        assert result['valid'] is True

    def test_address_mismatch(self):
        rd = '00' * 64
        result = verify_report_data_binding(rd, signing_address='0xdeadbeef')
        assert result['address_matches'] is False
        assert result['valid'] is False

    def test_nonce_match(self):
        rd = '00' * 32 + 'cafebabe' + '00' * 28
        result = verify_report_data_binding(rd, nonce='0xcafebabe')
        assert result['nonce_matches'] is True

    def test_short_report_data(self):
        result = verify_report_data_binding('aabb')
        assert 'error' in result

    def test_0x_prefix_handling(self):
        rd = '0x' + 'aa' * 32 + 'bb' * 32
        result = verify_report_data_binding(rd)
        assert result['valid'] is True
        assert result['report_data_first_32'] == 'aa' * 32


class TestVerifyQuoteDcap:
    @patch('dstack_audit.phases.attestation.subprocess')
    def test_dcap_qvl_not_installed(self, mock_subprocess):
        """Returns error when dcap-qvl is not found."""
        mock_subprocess.run.side_effect = FileNotFoundError()
        qv = verify_quote_dcap('0x' + 'ab' * 100)
        assert qv.verified is False
        assert 'not installed' in qv.error

    @patch('dstack_audit.phases.attestation.subprocess')
    def test_dcap_qvl_success(self, mock_subprocess):
        """Parses dcap-qvl JSON output correctly."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({
            'status': 'UpToDate',
            'report': {
                'TD10': {
                    'mr_config_id': '01' + 'aa' * 32 + '00' * 15,
                    'mr_td': 'bb' * 48,
                    'rtmr0': 'cc' * 48,
                    'rtmr1': 'dd' * 48,
                    'rtmr2': 'ee' * 48,
                    'rtmr3': 'ff' * 48,
                    'report_data': '11' * 64,
                }
            }
        })
        mock_subprocess.run.return_value = mock_result
        qv = verify_quote_dcap('0x' + 'ab' * 100)
        assert qv.verified is True
        assert qv.tcb_status == 'UpToDate'
        assert qv.mr_config_id.startswith('01')
        assert qv.rtmr0 == 'cc' * 48

    @patch('dstack_audit.phases.attestation.subprocess')
    def test_dcap_qvl_failure(self, mock_subprocess):
        """Handles dcap-qvl returning non-zero exit code."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = 'verification failed'
        mock_subprocess.run.return_value = mock_result
        qv = verify_quote_dcap('0x' + 'ab' * 100)
        assert qv.verified is False
        assert 'failed' in qv.error

    def test_short_quote(self):
        qv = verify_quote_dcap('0xaabb')
        assert qv.error is not None
        assert 'too short' in qv.error.lower()


class TestVerifyDstackService:
    @patch('dstack_audit.phases.attestation.urllib.request.urlopen')
    def test_service_not_running(self, mock_urlopen):
        """Falls back gracefully when service is not running."""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError('Connection refused')
        dv = verify_with_dstack_service('0x' + 'ab' * 100)
        assert dv.verified is False
        assert 'not running' in dv.error

    @patch('dstack_audit.phases.attestation.urllib.request.urlopen')
    def test_service_success(self, mock_urlopen):
        """Parses successful verification response."""
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = json.dumps({
            'app_valid': True,
            'kms_valid': True,
            'gateway_valid': True,
            'compose_hash': 'aabbcc',
        }).encode()
        mock_urlopen.return_value = mock_resp
        dv = verify_with_dstack_service('0xab' * 100)
        assert dv.verified is True
        assert dv.app_valid is True
        assert dv.kms_valid is True


class TestStageAssessmentWithVerification:
    """Test that stage assessment uses verification results."""

    def test_compose_hash_mismatch_creates_finding(self):
        from dstack_audit.models import (
            AttestationResult, CodeAnalysisResult, CrossReferenceResult,
            Finding, Stage, TLSResult,
        )
        from dstack_audit.phases.stage_assessment import assess_stage

        qv = QuoteVerification(
            verified=True,
            compose_hash_matches=False,
            tcb_status='UpToDate',
        )
        attestation = AttestationResult(
            has_tdx_quote=True,
            kms_enabled=True,
            quote_verification=qv,
        )
        stage, findings = assess_stage(
            attestation=attestation,
            tls=TLSResult(),
            code=CodeAnalysisResult(),
            xref=CrossReferenceResult(),
            findings=[],
        )
        assert any('compose_hash_mismatch' == f.category for f in findings)

    def test_verified_quote_sets_checklist(self):
        from dstack_audit.models import (
            AttestationResult, CodeAnalysisResult, CrossReferenceResult,
            TLSResult,
        )
        from dstack_audit.phases.stage_assessment import assess_stage

        qv = QuoteVerification(
            verified=True,
            compose_hash_matches=True,
            tcb_status='UpToDate',
        )
        attestation = AttestationResult(
            has_tdx_quote=True,
            kms_enabled=True,
            quote_verification=qv,
        )
        stage, _ = assess_stage(
            attestation=attestation,
            tls=TLSResult(),
            code=CodeAnalysisResult(),
            xref=CrossReferenceResult(),
            findings=[],
        )
        assert stage.stage1_checklist.get('quote_verified') is True
        assert stage.stage1_checklist.get('compose_hash_verified') is True

    def test_unverified_quote_sets_checklist_false(self):
        from dstack_audit.models import (
            AttestationResult, CodeAnalysisResult, CrossReferenceResult,
            TLSResult,
        )
        from dstack_audit.phases.stage_assessment import assess_stage

        qv = QuoteVerification(
            verified=False,
            error="dcap-qvl not installed",
        )
        attestation = AttestationResult(
            has_tdx_quote=True,
            kms_enabled=True,
            quote_verification=qv,
        )
        stage, _ = assess_stage(
            attestation=attestation,
            tls=TLSResult(),
            code=CodeAnalysisResult(),
            xref=CrossReferenceResult(),
            findings=[],
        )
        assert stage.stage1_checklist.get('quote_verified') is False
