"""Tests for Phase 2: Attestation."""
import json
import pytest
from dstack_audit.phases.attestation import (
    extract_app_compose_from_html,
    compute_compose_hash,
    fetch_attestation,
)


SAMPLE_APP_COMPOSE = {
    "manifest_version": 2,
    "name": "test-app",
    "runner": "docker-compose",
    "docker_compose_file": "version: '3'\nservices:\n  app:\n    image: test:latest\n",
    "kms_enabled": True,
    "gateway_enabled": True,
    "public_logs": False,
    "public_sysinfo": False,
    "allowed_envs": ["FOO", "BAR"],
    "no_instance_id": False,
    "secure_time": True,
}


def make_8090_html(app_compose: dict, quote: str = "0xabcdef1234") -> str:
    """Generate synthetic 8090 HTML with embedded app_compose."""
    compose_json = json.dumps(json.dumps(app_compose))
    # The HTML structure mimics the tappd info page
    return f'''<html>
<body>
<div>
"app_compose": {compose_json},
"quote": "{quote}",
"instance_id": "test"
</div>
</body>
</html>'''


class TestExtractAppCompose:
    def test_extract_from_html(self):
        html = make_8090_html(SAMPLE_APP_COMPOSE)
        result = extract_app_compose_from_html(html)
        assert result is not None
        assert result['name'] == 'test-app'
        assert result['kms_enabled'] is True
        assert result['allowed_envs'] == ['FOO', 'BAR']

    def test_extract_missing(self):
        result = extract_app_compose_from_html("<html><body>nothing</body></html>")
        assert result is None

    def test_extract_with_special_chars(self):
        compose = dict(SAMPLE_APP_COMPOSE)
        compose['docker_compose_file'] = 'image: "test:v1"\ncommand: "echo \\"hello\\""'
        html = make_8090_html(compose)
        result = extract_app_compose_from_html(html)
        assert result is not None
        assert 'test:v1' in result['docker_compose_file']


class TestComputeComposeHash:
    def test_deterministic(self):
        h1 = compute_compose_hash(SAMPLE_APP_COMPOSE)
        h2 = compute_compose_hash(SAMPLE_APP_COMPOSE)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_order_independent(self):
        """JSON keys are sorted, so order shouldn't matter."""
        from collections import OrderedDict
        compose1 = {"b": 2, "a": 1}
        compose2 = OrderedDict([("a", 1), ("b", 2)])
        assert compute_compose_hash(compose1) == compute_compose_hash(compose2)

    def test_different_content_different_hash(self):
        compose2 = dict(SAMPLE_APP_COMPOSE)
        compose2['name'] = 'different-app'
        assert compute_compose_hash(SAMPLE_APP_COMPOSE) != compute_compose_hash(compose2)


class TestFetchAttestation:
    def test_with_tdx_quote(self):
        """Test parsing HTML with a TDX quote present."""
        html = make_8090_html(SAMPLE_APP_COMPOSE, quote="0x" + "ab" * 100)
        # We can't call fetch_attestation directly without a server,
        # but we can test the extraction logic
        compose = extract_app_compose_from_html(html)
        assert compose is not None
        assert compose['kms_enabled'] is True

    def test_without_tdx_quote(self):
        """Test parsing HTML with empty quote (--dev-os)."""
        html = make_8090_html(SAMPLE_APP_COMPOSE, quote="")
        compose = extract_app_compose_from_html(html)
        assert compose is not None
        # Quote detection is in fetch_attestation, but compose extraction works
