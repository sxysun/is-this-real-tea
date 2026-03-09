"""Live tests that hit real Phala Cloud endpoints.

Run with: pytest dstack-audit-tests/test_live.py --run-live -v
"""
import pytest

from dstack_audit.pipeline import run_audit
from dstack_audit.models import Stage


@pytest.mark.live
class TestLiveAudit:
    """Tests against real Phala Cloud endpoints. Requires network access."""

    def test_tee_totalled(self):
        report = run_audit(
            "https://github.com/sangaline/tee-totalled",
            "https://4e0b5429671d8f90198c806f93e3c0a483f64cff-3000.dstack-pha-prod7.phala.network/",
            verbose=True,
        )
        assert report.stage == Stage.STAGE_0
        # Must find configurable LLM_BASE_URL
        finding_titles = ' '.join(f.title for f in report.findings)
        finding_details = ' '.join(f.detail for f in report.findings)
        all_text = finding_titles + finding_details
        assert 'LLM_BASE_URL' in all_text or 'configurable' in all_text.lower()
