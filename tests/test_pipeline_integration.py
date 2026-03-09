"""Integration tests: full pipeline with synthetic and fixture data."""
import json
import os
import tempfile
import pytest
from unittest.mock import patch, MagicMock

from dstack_audit.models import Severity, Stage
from dstack_audit.pipeline import run_audit
from dstack_audit.phases.attestation import extract_app_compose_from_html, compute_compose_hash
from dstack_audit.report import generate_report


def make_synthetic_8090_html(
    name="test-app",
    kms_enabled=True,
    has_quote=True,
    allowed_envs=None,
    docker_compose="version: '3'\nservices:\n  app:\n    image: test:latest\n",
):
    """Build synthetic 8090 HTML for testing."""
    if allowed_envs is None:
        allowed_envs = []

    app_compose = {
        "manifest_version": 2,
        "name": name,
        "runner": "docker-compose",
        "docker_compose_file": docker_compose,
        "kms_enabled": kms_enabled,
        "gateway_enabled": True,
        "public_logs": False,
        "public_sysinfo": False,
        "allowed_envs": allowed_envs,
        "no_instance_id": False,
        "secure_time": True,
    }

    compose_json = json.dumps(json.dumps(app_compose))
    quote = "0x" + "ab" * 200 if has_quote else ""

    return f'''"app_compose": {compose_json}, "quote": "{quote}"'''


class TestSyntheticPipeline:
    """Test full pipeline with mocked network calls."""

    @patch('dstack_audit.phases.attestation.fetch_html')
    @patch('dstack_audit.phases.tls_binding.get_cert_fingerprint')
    @patch('dstack_audit.phases.code_analysis.clone_repo')
    def test_dev_os_detected(self, mock_clone, mock_cert, mock_html):
        """App without TDX quote should be Stage 0."""
        mock_html.return_value = make_synthetic_8090_html(has_quote=False)
        mock_cert.return_value = "abc123"

        # Create synthetic repo
        tmpdir = tempfile.mkdtemp()
        os.makedirs(os.path.join(tmpdir, 'src'), exist_ok=True)
        with open(os.path.join(tmpdir, 'docker-compose.yaml'), 'w') as f:
            f.write("version: '3'\nservices:\n  app:\n    image: test:latest\n")
        with open(os.path.join(tmpdir, 'src', 'main.py'), 'w') as f:
            f.write("print('hello')\n")
        mock_clone.return_value = tmpdir

        report = run_audit(
            "https://github.com/test/repo",
            "https://ab8511-3000.dstack-pha-prod7.phala.network/",
        )

        assert report.stage == Stage.STAGE_0
        assert report.attestation is not None
        assert report.attestation.has_tdx_quote is False

        # Verify report generates
        md = generate_report(report)
        assert '0 (Ruggable)' in md

        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

    @patch('dstack_audit.phases.attestation.fetch_html')
    @patch('dstack_audit.phases.tls_binding.get_cert_fingerprint')
    @patch('dstack_audit.phases.code_analysis.clone_repo')
    def test_configurable_url_detected(self, mock_clone, mock_cert, mock_html):
        """App with LLM_BASE_URL in allowed_envs should flag exfiltration."""
        compose = "version: '3'\nservices:\n  app:\n    image: test:latest\n    environment:\n      - LLM_BASE_URL=${LLM_BASE_URL}\n"
        mock_html.return_value = make_synthetic_8090_html(
            name="tee-totalled",
            allowed_envs=["LLM_BASE_URL"],
            docker_compose=compose,
        )
        mock_cert.return_value = "abc123"

        tmpdir = tempfile.mkdtemp()
        with open(os.path.join(tmpdir, 'docker-compose.yaml'), 'w') as f:
            f.write(compose)
        os.makedirs(os.path.join(tmpdir, 'src'), exist_ok=True)
        with open(os.path.join(tmpdir, 'src', 'app.py'), 'w') as f:
            f.write('import requests\nurl = os.environ["LLM_BASE_URL"]\nrequests.post(url)\n')
        mock_clone.return_value = tmpdir

        report = run_audit(
            "https://github.com/sangaline/tee-totalled",
            "https://4e0b5429671d8f90198c806f93e3c0a483f64cff-3000.dstack-pha-prod7.phala.network/",
        )

        assert report.stage == Stage.STAGE_0
        finding_titles = [f.title for f in report.findings]
        assert any('LLM_BASE_URL' in t for t in finding_titles)

        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

    @patch('dstack_audit.phases.attestation.fetch_html')
    @patch('dstack_audit.phases.tls_binding.get_cert_fingerprint')
    @patch('dstack_audit.phases.code_analysis.clone_repo')
    def test_variable_image_detected(self, mock_clone, mock_cert, mock_html):
        """App with ${VAR} image refs should flag as critical."""
        compose = "version: '3'\nservices:\n  app:\n    image: ${APP_IMAGE}\n"
        mock_html.return_value = make_synthetic_8090_html(
            allowed_envs=["APP_IMAGE"],
            docker_compose=compose,
        )
        mock_cert.return_value = "abc123"

        tmpdir = tempfile.mkdtemp()
        with open(os.path.join(tmpdir, 'docker-compose.yaml'), 'w') as f:
            f.write(compose)
        mock_clone.return_value = tmpdir

        report = run_audit(
            "https://github.com/test/tokscope",
            "https://f44389-3000.dstack-pha-prod9.phala.network/",
        )

        assert report.stage == Stage.STAGE_0
        assert any(f.category == 'variable_image' for f in report.findings)

        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

    @patch('dstack_audit.phases.attestation.fetch_html')
    @patch('dstack_audit.phases.tls_binding.get_cert_fingerprint')
    @patch('dstack_audit.phases.code_analysis.clone_repo')
    def test_mutable_image_detected(self, mock_clone, mock_cert, mock_html):
        """App with image:latest should flag mutable tags."""
        compose = "version: '3'\nservices:\n  app:\n    image: myapp:latest\n"
        mock_html.return_value = make_synthetic_8090_html(docker_compose=compose)
        mock_cert.return_value = "abc123"

        tmpdir = tempfile.mkdtemp()
        with open(os.path.join(tmpdir, 'docker-compose.yaml'), 'w') as f:
            f.write(compose)
        mock_clone.return_value = tmpdir

        report = run_audit(
            "https://github.com/test/repo",
            "https://db82f5-3000.dstack-pha-prod9.phala.network/",
        )

        assert report.stage == Stage.STAGE_0
        assert any(f.category == 'mutable_image' for f in report.findings)

        md = generate_report(report)
        assert 'mutable' in md.lower() or 'Mutable' in md

        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

    @patch('dstack_audit.phases.attestation.fetch_html')
    @patch('dstack_audit.phases.tls_binding.get_cert_fingerprint')
    @patch('dstack_audit.phases.code_analysis.clone_repo')
    def test_report_generation(self, mock_clone, mock_cert, mock_html):
        """Full report should contain all sections."""
        mock_html.return_value = make_synthetic_8090_html()
        mock_cert.return_value = "abc123"

        tmpdir = tempfile.mkdtemp()
        with open(os.path.join(tmpdir, 'docker-compose.yaml'), 'w') as f:
            f.write("version: '3'\nservices:\n  app:\n    image: test:latest\n")
        mock_clone.return_value = tmpdir

        report = run_audit(
            "https://github.com/test/repo",
            "https://db82f5-3000.dstack-pha-prod9.phala.network/",
        )

        md = generate_report(report)
        assert '# dstack-audit Report' in md
        assert 'Phase 1: URL Parsing' in md
        assert 'Phase 2: Attestation' in md
        assert 'Phase 6: Stage Assessment' in md
        assert 'Stage 1 Checklist' in md

        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
