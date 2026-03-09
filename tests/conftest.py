"""Fixtures and case study definitions for dstack-audit tests."""
import os
import json
import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--run-live", action="store_true", default=False,
        help="Run live tests against Phala Cloud endpoints",
    )


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--run-live"):
        skip = pytest.mark.skip(reason="Live tests require --run-live")
        for item in items:
            if "live" in item.keywords:
                item.add_marker(skip)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')

# Case study definitions with known expected results
CASE_STUDIES = {
    'hermes': {
        'app_id': 'db82f5',
        'cluster': 'dstack-pha-prod9',
        'repo_url': 'https://github.com/example/hermes',
        'website_url': 'https://db82f5-3000.dstack-pha-prod9.phala.network/',
        'expected_stage': 0,
        'must_find': ['Pha KMS', 'mutable image'],
        'fixture_dir': 'hermes',
    },
    'tee-totalled': {
        'app_id': '4e0b5429671d8f90198c806f93e3c0a483f64cff',
        'cluster': 'dstack-pha-prod7',
        'repo_url': 'https://github.com/sangaline/tee-totalled',
        'website_url': 'https://4e0b5429671d8f90198c806f93e3c0a483f64cff-3000.dstack-pha-prod7.phala.network/',
        'expected_stage': 0,
        'must_find': ['LLM_BASE_URL', 'configurable'],
        'fixture_dir': 'tee-totalled',
    },
    'tokscope-xordi': {
        'app_id': 'f44389',
        'cluster': 'dstack-pha-prod9',
        'repo_url': 'https://github.com/example/tokscope-xordi',
        'website_url': 'https://f44389-3000.dstack-pha-prod9.phala.network/',
        'expected_stage': 0,
        'must_find': ['${VAR}', 'variable image', 'allowed_envs'],
        'fixture_dir': 'tokscope-xordi',
    },
    'xordi-toy-example': {
        'app_id': 'f9d35f',
        'cluster': 'dstack-base-prod9',
        'repo_url': 'https://github.com/example/xordi-toy-example',
        'website_url': 'https://f9d35f-3000.dstack-base-prod9.phala.network/',
        'expected_stage': 0,
        'must_find': ['MOCK_API_URL', 'exfiltration'],
        'fixture_dir': 'xordi-toy-example',
    },
    'firecrawl': {
        'app_id': 'ab8511',
        'cluster': 'dstack-pha-prod7',
        'repo_url': 'https://github.com/example/firecrawl',
        'website_url': 'https://ab8511-3000.dstack-pha-prod7.phala.network/',
        'expected_stage': 0,
        'must_find': ['No TDX quote', '--dev-os'],
        'fixture_dir': 'firecrawl',
    },
}


def load_fixture(case_name: str, filename: str) -> str | None:
    """Load a fixture file for a case study."""
    path = os.path.join(FIXTURES_DIR, CASE_STUDIES[case_name]['fixture_dir'], filename)
    if os.path.exists(path):
        with open(path) as f:
            return f.read()
    return None


def load_json_fixture(case_name: str, filename: str) -> dict | None:
    """Load a JSON fixture file."""
    content = load_fixture(case_name, filename)
    if content:
        return json.loads(content)
    return None


@pytest.fixture
def case_studies():
    return CASE_STUDIES


@pytest.fixture(params=list(CASE_STUDIES.keys()))
def case_study(request):
    """Parametrized fixture providing each case study."""
    return CASE_STUDIES[request.param]
