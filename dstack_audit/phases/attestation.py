"""Phase 2: Fetch attestation from 8090 endpoint and extract app_compose."""
import hashlib
import html as html_module
import json
import re
import urllib.request

from ..models import AttestationResult


def fetch_html(url: str) -> str:
    req = urllib.request.Request(url, headers={'User-Agent': 'dstack-audit/1.0'})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode('utf-8')


def fetch_json(url: str):
    req = urllib.request.Request(url, headers={'User-Agent': 'dstack-audit/1.0'})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def extract_app_compose_from_html(html_content: str) -> dict | None:
    """Extract app_compose JSON from tappd info page (8090)."""
    content = html_module.unescape(html_content)
    match = re.search(r'"app_compose":\s*"((?:[^"\\]|\\.)*)"', content, re.DOTALL)
    if not match:
        return None
    escaped = match.group(1)
    compose_json = json.loads('"' + escaped + '"')
    return json.loads(compose_json)


def compute_compose_hash(compose_obj: dict) -> str:
    """Compute compose hash matching dstack's canonical JSON."""
    canonical = json.dumps(compose_obj, separators=(',', ':'), sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def fetch_attestation(info_url: str) -> AttestationResult:
    """Fetch and parse attestation data from the 8090 endpoint.

    Args:
        info_url: The https://{app_id}-8090.{cluster}.phala.network/ URL
    """
    result = AttestationResult()

    try:
        html_content = fetch_html(info_url)
        result.raw_html = html_content
    except Exception as e:
        result.error = f"Failed to fetch 8090 endpoint: {e}"
        return result

    compose = extract_app_compose_from_html(html_content)
    if not compose:
        result.error = "Could not extract app_compose from 8090 HTML"
        return result

    result.app_compose = compose
    result.compose_hash = compute_compose_hash(compose)
    result.app_name = compose.get('name', '')
    result.kms_enabled = compose.get('kms_enabled', False)
    result.allowed_envs = compose.get('allowed_envs', [])
    result.docker_compose_file = compose.get('docker_compose_file', '')
    result.pre_launch_script = compose.get('pre_launch_script', '')

    # Check for TDX quote in the HTML
    # The quote is typically in a field like "quote": "0x..." or in a textarea
    quote_match = re.search(r'"quote":\s*"(0x[a-fA-F0-9]+)"', html_content)
    if quote_match:
        result.has_tdx_quote = True
        result.quote_hex = quote_match.group(1)
    else:
        # Also check for empty quote indicating --dev-os
        empty_quote = re.search(r'"quote":\s*""', html_content)
        if empty_quote:
            result.has_tdx_quote = False
        else:
            # Try looking for any hex blob that looks like a quote (>100 chars)
            big_hex = re.search(r'"quote":\s*"([^"]{100,})"', html_content)
            if big_hex:
                result.has_tdx_quote = True
                result.quote_hex = big_hex.group(1)
            else:
                result.has_tdx_quote = False

    return result


def fetch_cloud_api_attestation(app_id: str) -> dict | None:
    """Fetch attestation from Phala Cloud API (supplementary)."""
    url = f"https://cloud-api.phala.network/api/v1/apps/{app_id}/attestations"
    try:
        return fetch_json(url)
    except Exception:
        return None
