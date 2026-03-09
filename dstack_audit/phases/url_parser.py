"""Phase 1: Parse Phala Cloud URLs to extract app_id, cluster, port."""
import re
import subprocess
from urllib.parse import urlparse

from ..models import ParsedURL

# Pattern: {app_id}-{port}[s].{cluster}.phala.network
PHALA_URL_RE = re.compile(
    r'^(?P<app_id>[a-f0-9]+)-(?P<port>\d+)(?P<tls>s)?\.(?P<cluster>[a-z0-9-]+)\.phala\.network$'
)


def parse_phala_url(url: str) -> ParsedURL:
    """Parse a Phala Cloud gateway URL into components.

    Handles:
      https://{app_id}-{port}[s].{cluster}.phala.network/...
      Custom domains via _dstack-app-address DNS TXT lookup
    """
    parsed = urlparse(url if '://' in url else f'https://{url}')
    host = parsed.hostname or ''

    m = PHALA_URL_RE.match(host)
    if m:
        return ParsedURL(
            app_id=m.group('app_id'),
            cluster=m.group('cluster'),
            port=int(m.group('port')),
            tls_passthrough=bool(m.group('tls')),
            original_url=url,
        )

    # Try custom domain: look up _dstack-app-address TXT record
    txt_host = f"_dstack-app-address.{host}"
    try:
        result = subprocess.run(
            ['dig', '+short', 'TXT', txt_host],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.strip().splitlines():
            txt_value = line.strip().strip('"')
            m2 = PHALA_URL_RE.match(txt_value)
            if m2:
                return ParsedURL(
                    app_id=m2.group('app_id'),
                    cluster=m2.group('cluster'),
                    port=int(m2.group('port')),
                    tls_passthrough=bool(m2.group('tls')),
                    original_url=url,
                )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    raise ValueError(
        f"Cannot parse Phala URL: {url}\n"
        f"Expected format: https://{{app_id}}-{{port}}[s].{{cluster}}.phala.network/"
    )


def get_info_url(parsed: ParsedURL) -> str:
    """Build the 8090 info/attestation endpoint URL."""
    return f"https://{parsed.app_id}-8090.{parsed.cluster}.phala.network/"


def get_app_url(parsed: ParsedURL) -> str:
    """Build the app endpoint URL."""
    suffix = 's' if parsed.tls_passthrough else ''
    return f"https://{parsed.app_id}-{parsed.port}{suffix}.{parsed.cluster}.phala.network/"
