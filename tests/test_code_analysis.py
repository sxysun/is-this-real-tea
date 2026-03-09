"""Tests for Phase 4: Code analysis with synthetic repos."""
import json
import os
import tempfile
import pytest
from dstack_audit.phases.code_analysis import analyze_code, grep_repo, load_search_patterns


@pytest.fixture
def synthetic_repo():
    """Create a temporary directory with synthetic source files."""
    tmpdir = tempfile.mkdtemp(prefix='dstack-audit-test-')

    # docker-compose.yaml with configurable URL
    os.makedirs(os.path.join(tmpdir, 'deploy'), exist_ok=True)
    with open(os.path.join(tmpdir, 'deploy', 'docker-compose.yaml'), 'w') as f:
        f.write('''version: '3'
services:
  app:
    image: myapp:latest
    environment:
      - LLM_BASE_URL=${LLM_BASE_URL}
      - API_KEY=${API_KEY}
      - MOCK_API_URL=${MOCK_API_URL}
  worker:
    image: ${WORKER_IMAGE}
''')

    # Python source with various patterns
    os.makedirs(os.path.join(tmpdir, 'src'), exist_ok=True)
    with open(os.path.join(tmpdir, 'src', 'main.py'), 'w') as f:
        f.write('''import requests
import os

LLM_URL = os.environ.get("LLM_BASE_URL", "https://api.openai.com")

def call_llm(prompt):
    # HACK: this is a temporary workaround
    resp = requests.post(LLM_URL + "/v1/chat", json={"prompt": prompt})
    return resp.json()

def get_attestation():
    from tappd import TappdClient
    client = TappdClient()
    quote = client.tdxQuote()
    return quote
''')

    # Dockerfile
    with open(os.path.join(tmpdir, 'Dockerfile'), 'w') as f:
        f.write('''FROM python:3.12
ENV SOURCE_DATE_EPOCH=0
COPY . /app
RUN pip install -r requirements.txt
''')

    # Smart contract reference
    with open(os.path.join(tmpdir, 'src', 'contract.py'), 'w') as f:
        f.write('''
APP_AUTH_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678"
# AppAuth contract for compose hash verification
def check_appauth(compose_hash):
    pass
''')

    yield tmpdir

    # Cleanup
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)


class TestGrepRepo:
    def test_grep_finds_pattern(self, synthetic_repo):
        matches = grep_repo(synthetic_repo, 'LLM_BASE_URL')
        assert len(matches) > 0
        assert any('LLM_BASE_URL' in m['content'] for m in matches)

    def test_grep_with_glob(self, synthetic_repo):
        matches = grep_repo(synthetic_repo, 'image:', '*.yaml')
        assert len(matches) > 0

    def test_grep_no_match(self, synthetic_repo):
        matches = grep_repo(synthetic_repo, 'NONEXISTENT_PATTERN_XYZ')
        assert len(matches) == 0


class TestAnalyzeCode:
    def test_finds_configurable_urls(self, synthetic_repo):
        result = analyze_code(synthetic_repo)
        assert len(result.configurable_urls) > 0
        contents = [m['content'] for m in result.configurable_urls]
        assert any('LLM_BASE_URL' in c for c in contents)

    def test_finds_external_network_calls(self, synthetic_repo):
        result = analyze_code(synthetic_repo)
        assert len(result.external_network_calls) > 0
        contents = [m['content'] for m in result.external_network_calls]
        assert any('requests.post' in c for c in contents)

    def test_finds_red_flags(self, synthetic_repo):
        result = analyze_code(synthetic_repo)
        assert len(result.red_flags) > 0
        contents = [m['content'] for m in result.red_flags]
        assert any('HACK' in c for c in contents)

    def test_finds_attestation_code(self, synthetic_repo):
        result = analyze_code(synthetic_repo)
        assert len(result.attestation_code) > 0
        contents = [m['content'] for m in result.attestation_code]
        assert any('TappdClient' in c or 'tdxQuote' in c for c in contents)

    def test_finds_build_reproducibility(self, synthetic_repo):
        result = analyze_code(synthetic_repo)
        assert len(result.build_reproducibility) > 0
        contents = [m['content'] for m in result.build_reproducibility]
        assert any('SOURCE_DATE_EPOCH' in c for c in contents)

    def test_finds_smart_contracts(self, synthetic_repo):
        result = analyze_code(synthetic_repo)
        assert len(result.smart_contracts) > 0
        contents = [m['content'] for m in result.smart_contracts]
        assert any('AppAuth' in c or '0x1234' in c for c in contents)

    def test_finds_secrets_storage(self, synthetic_repo):
        result = analyze_code(synthetic_repo)
        assert len(result.secrets_storage) > 0


class TestSearchPatterns:
    def test_patterns_load(self):
        patterns = load_search_patterns()
        assert 'configurable_urls' in patterns
        assert 'external_network_calls' in patterns
        assert 'red_flags' in patterns
        assert len(patterns) == 7

    def test_each_pattern_has_required_fields(self):
        patterns = load_search_patterns()
        for category, pats in patterns.items():
            for pat in pats:
                assert 'pattern' in pat, f"Missing 'pattern' in {category}/{pat}"
                assert 'name' in pat, f"Missing 'name' in {category}/{pat}"
