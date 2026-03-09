"""Phase 3: Verify TLS certificate binding to attestation."""
import hashlib
import json
import socket
import ssl
import urllib.request
from urllib.parse import urlparse

from ..models import TLSResult


def get_cert_fingerprint(host: str, port: int) -> str:
    """Get SHA256 fingerprint of server's TLS certificate."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
        s.settimeout(10)
        s.connect((host, port))
        cert_der = s.getpeercert(binary_form=True)
        return hashlib.sha256(cert_der).hexdigest()


def fetch_attestation_endpoint(base_url: str) -> dict | None:
    """Try to fetch /attestation from the app endpoint."""
    url = base_url.rstrip('/') + '/attestation'
    try:
        # Create SSL context that doesn't verify (for self-signed TEE certs)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, headers={'User-Agent': 'dstack-audit/1.0'})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def verify_tls_binding(website_url: str, tls_passthrough: bool) -> TLSResult:
    """Verify TLS certificate is bound to TEE attestation.

    Args:
        website_url: The app's public URL
        tls_passthrough: Whether the URL uses TLS passthrough (port suffix 's')
    """
    result = TLSResult()
    parsed = urlparse(website_url if '://' in website_url else f'https://{website_url}')
    host = parsed.hostname
    port = parsed.port or 443

    if not tls_passthrough:
        result.gateway_terminated = True
        # Gateway-terminated TLS: cert is from the gateway, not the TEE
        # We can still get the fingerprint but it won't match TEE attestation
        try:
            result.cert_fingerprint = get_cert_fingerprint(host, port)
        except Exception as e:
            result.error = f"Failed to get certificate: {e}"
        return result

    # TLS passthrough: cert should be from the TEE itself
    try:
        result.cert_fingerprint = get_cert_fingerprint(host, port)
    except Exception as e:
        result.error = f"Failed to get certificate: {e}"
        return result

    # Try to fetch /attestation to compare fingerprints
    attestation = fetch_attestation_endpoint(website_url)
    if attestation:
        result.has_attestation_endpoint = True
        result.attested_fingerprint = attestation.get('certFingerprint')
        if result.attested_fingerprint and result.cert_fingerprint:
            result.fingerprints_match = (
                result.cert_fingerprint == result.attested_fingerprint
            )
    else:
        result.has_attestation_endpoint = False

    return result
