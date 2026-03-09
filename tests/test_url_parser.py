"""Tests for Phase 1: URL parsing."""
import pytest
from dstack_audit.phases.url_parser import parse_phala_url, get_info_url, get_app_url


class TestParsePhalaUrl:
    def test_standard_url(self):
        url = "https://db82f5-3000.dstack-pha-prod9.phala.network/"
        parsed = parse_phala_url(url)
        assert parsed.app_id == "db82f5"
        assert parsed.cluster == "dstack-pha-prod9"
        assert parsed.port == 3000
        assert parsed.tls_passthrough is False

    def test_tls_passthrough(self):
        url = "https://abc123-8443s.dstack-pha-prod7.phala.network/"
        parsed = parse_phala_url(url)
        assert parsed.app_id == "abc123"
        assert parsed.port == 8443
        assert parsed.tls_passthrough is True

    def test_long_app_id(self):
        url = "https://4e0b5429671d8f90198c806f93e3c0a483f64cff-3000.dstack-pha-prod7.phala.network/"
        parsed = parse_phala_url(url)
        assert parsed.app_id == "4e0b5429671d8f90198c806f93e3c0a483f64cff"
        assert parsed.cluster == "dstack-pha-prod7"
        assert parsed.port == 3000

    def test_without_scheme(self):
        url = "db82f5-3000.dstack-pha-prod9.phala.network"
        parsed = parse_phala_url(url)
        assert parsed.app_id == "db82f5"

    def test_with_path(self):
        url = "https://db82f5-3000.dstack-pha-prod9.phala.network/some/path"
        parsed = parse_phala_url(url)
        assert parsed.app_id == "db82f5"

    def test_base_cluster(self):
        url = "https://f9d35f-3000.dstack-base-prod9.phala.network/"
        parsed = parse_phala_url(url)
        assert parsed.cluster == "dstack-base-prod9"

    def test_invalid_url(self):
        with pytest.raises(ValueError, match="Cannot parse Phala URL"):
            parse_phala_url("https://example.com/")

    def test_8090_port(self):
        url = "https://db82f5-8090.dstack-pha-prod9.phala.network/"
        parsed = parse_phala_url(url)
        assert parsed.port == 8090


class TestGetInfoUrl:
    def test_info_url(self):
        from dstack_audit.models import ParsedURL
        parsed = ParsedURL(app_id="db82f5", cluster="dstack-pha-prod9", port=3000,
                           tls_passthrough=False)
        assert get_info_url(parsed) == "https://db82f5-8090.dstack-pha-prod9.phala.network/"


class TestGetAppUrl:
    def test_no_passthrough(self):
        from dstack_audit.models import ParsedURL
        parsed = ParsedURL(app_id="abc", cluster="dstack-pha-prod7", port=3000,
                           tls_passthrough=False)
        assert get_app_url(parsed) == "https://abc-3000.dstack-pha-prod7.phala.network/"

    def test_with_passthrough(self):
        from dstack_audit.models import ParsedURL
        parsed = ParsedURL(app_id="abc", cluster="dstack-pha-prod7", port=8443,
                           tls_passthrough=True)
        assert get_app_url(parsed) == "https://abc-8443s.dstack-pha-prod7.phala.network/"
