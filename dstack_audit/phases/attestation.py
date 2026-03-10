"""Phase 2: Fetch attestation from 8090 endpoint and extract app_compose."""
import hashlib
import html as html_module
import json
import os
import re
import struct
import subprocess
import tempfile
import urllib.request

from ..models import AttestationResult, DstackVerification, QuoteVerification


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


def fetch_cloud_api_full(app_id: str) -> dict | None:
    """Fetch full attestation data (quote, event_log, vm_config) from Cloud API.

    Returns dict with keys: instances, kms_info, gateway_info — each containing
    quote, event_log, vm_config for the respective component.
    """
    url = f"https://cloud-api.phala.network/api/v1/apps/{app_id}/attestations"
    try:
        data = fetch_json(url)
        result = {}
        # Extract per-instance data
        instances = data.get('instances', [])
        if instances:
            inst = instances[0]
            result['app_quote'] = inst.get('quote', '')
            result['app_event_log'] = inst.get('event_log', '')
            result['app_vm_config'] = inst.get('vm_config', '')
            result['image_version'] = inst.get('image_version', '')
        # KMS info
        kms = data.get('kms_info', {})
        if kms:
            result['kms_quote'] = kms.get('quote', '')
            result['kms_event_log'] = kms.get('event_log', '')
            result['kms_version'] = kms.get('version', '')
        # Gateway info
        gw = data.get('gateway_info', {})
        if gw:
            result['gw_quote'] = gw.get('quote', '')
            result['gw_event_log'] = gw.get('event_log', '')
        result['raw'] = data
        return result
    except Exception:
        return None


# --- Cryptographic verification functions ---


def verify_quote_dcap(quote_hex: str) -> QuoteVerification:
    """Verify TDX quote with dcap-qvl CLI tool.

    Writes quote to temp file, calls `dcap-qvl verify --hex <file>`,
    parses JSON output for TCB status and measurements.
    """
    qv = QuoteVerification()

    try:
        # Remove 0x prefix if present
        raw_hex = quote_hex
        if raw_hex.startswith('0x'):
            raw_hex = raw_hex[2:]

        if not raw_hex or len(raw_hex) < 100:
            qv.error = "Quote too short to be a valid TDX quote"
            return qv

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.hex', delete=False
        ) as f:
            f.write(raw_hex)
            quote_path = f.name

        try:
            result = subprocess.run(
                ['dcap-qvl', 'verify', '--hex', quote_path],
                capture_output=True, text=True, timeout=60,
            )
        finally:
            os.unlink(quote_path)

        if result.returncode != 0:
            qv.error = f"dcap-qvl failed: {result.stderr.strip()}"
            return qv

        data = json.loads(result.stdout)
        qv.verified = True
        qv.tcb_status = data.get('status', 'unknown')

        # Extract measurements from TD10 report
        report = data.get('report', {}).get('TD10', {})
        qv.mr_config_id = report.get('mr_config_id', '')
        qv.mr_td = report.get('mr_td', '')
        qv.rtmr0 = report.get('rtmr0', '')
        qv.rtmr1 = report.get('rtmr1', '')
        qv.rtmr2 = report.get('rtmr2', '')
        qv.rtmr3 = report.get('rtmr3', '')
        qv.report_data = report.get('report_data', '')

    except FileNotFoundError:
        qv.error = "dcap-qvl not installed (install with: CFLAGS=\"-g0\" cargo install dcap-qvl-cli)"
    except json.JSONDecodeError as e:
        qv.error = f"Failed to parse dcap-qvl output: {e}"
    except subprocess.TimeoutExpired:
        qv.error = "dcap-qvl timed out after 60 seconds"
    except Exception as e:
        qv.error = f"Quote verification error: {e}"

    return qv


def parse_tdx_quote_manual(quote_hex: str) -> QuoteVerification:
    """Parse TDX quote fields manually without dcap-qvl.

    This extracts measurements but does NOT verify the quote signature.
    Use as a fallback when dcap-qvl is not installed.

    TDX Quote v4 structure (Intel DCAP):
      Header (48 bytes):
        version (2), att_key_type (2), tee_type (4), reserved (4),
        vendor_id (16), user_data (20)
      Body / TD Report (584 bytes starting at offset 48):
        tee_tcb_svn (16), mr_seam (48), mr_signer_seam (48), seam_attributes (8),
        td_attributes (8), xfam (8), mr_td (48), mr_config_id (48), mr_owner (48),
        mr_owner_config (48), rtmr0 (48), rtmr1 (48), rtmr2 (48), rtmr3 (48),
        report_data (64)
    """
    qv = QuoteVerification()

    try:
        raw_hex = quote_hex
        if raw_hex.startswith('0x'):
            raw_hex = raw_hex[2:]

        quote_bytes = bytes.fromhex(raw_hex)

        if len(quote_bytes) < 632:
            qv.error = f"Quote too short ({len(quote_bytes)} bytes, need >= 632)"
            return qv

        # Check version (offset 0, 2 bytes LE)
        version = struct.unpack_from('<H', quote_bytes, 0)[0]
        if version not in (4, 5):
            qv.error = f"Unexpected quote version: {version}"
            return qv

        # TD Report starts at offset 48
        td_offset = 48

        # mr_td: offset 48 + 80 = 128, length 48
        qv.mr_td = quote_bytes[td_offset + 80:td_offset + 128].hex()
        # mr_config_id: offset 48 + 128 = 176, length 48
        qv.mr_config_id = quote_bytes[td_offset + 128:td_offset + 176].hex()
        # rtmr0: offset 48 + 272 = 320, length 48
        qv.rtmr0 = quote_bytes[td_offset + 272:td_offset + 320].hex()
        # rtmr1: offset 48 + 320 = 368, length 48
        qv.rtmr1 = quote_bytes[td_offset + 320:td_offset + 368].hex()
        # rtmr2: offset 48 + 368 = 416, length 48
        qv.rtmr2 = quote_bytes[td_offset + 368:td_offset + 416].hex()
        # rtmr3: offset 48 + 416 = 464, length 48
        qv.rtmr3 = quote_bytes[td_offset + 416:td_offset + 464].hex()
        # report_data: offset 48 + 464 = 512, length 64
        qv.report_data = quote_bytes[td_offset + 464:td_offset + 528].hex()

        # Not cryptographically verified - just parsed
        qv.verified = False
        qv.tcb_status = "unverified (parsed manually, dcap-qvl not available)"

    except ValueError as e:
        qv.error = f"Invalid hex in quote: {e}"
    except Exception as e:
        qv.error = f"Manual quote parsing error: {e}"

    return qv


def verify_compose_hash_against_quote(
    computed_hash: str, quote_verification: QuoteVerification
) -> bool:
    """Compare computed compose hash against mr_config_id from verified quote.

    dstack encodes compose hash in mr_config_id as: '01' + 32-byte-hash + padding.
    The mr_config_id is 48 bytes (96 hex chars). Format:
      byte 0: 0x01 (version marker)
      bytes 1-32: SHA-256 of canonical JSON compose
      bytes 33-47: zero padding
    """
    config_id = quote_verification.mr_config_id
    if not config_id:
        return False

    # mr_config_id format: "01" + 64 hex chars (32 bytes hash) + padding
    if config_id.startswith('01'):
        quote_hash = config_id[2:66]  # 32 bytes = 64 hex chars
        return quote_hash == computed_hash

    return False


def verify_report_data_binding(
    report_data_hex: str,
    signing_address: str | None = None,
    nonce: str | None = None,
) -> dict:
    """Verify report_data binding: address and nonce embedded in quote.

    report_data is 64 bytes:
      bytes 0-31: signing address (or app-specific binding)
      bytes 32-63: nonce
    """
    result = {
        'valid': False,
        'address_matches': None,
        'nonce_matches': None,
        'report_data_first_32': None,
        'report_data_last_32': None,
    }

    try:
        rd_hex = report_data_hex
        if rd_hex.startswith('0x'):
            rd_hex = rd_hex[2:]

        if len(rd_hex) < 128:  # 64 bytes = 128 hex chars
            result['error'] = f"report_data too short ({len(rd_hex)} hex chars)"
            return result

        result['report_data_first_32'] = rd_hex[:64]
        result['report_data_last_32'] = rd_hex[64:128]

        checks_passed = True

        if signing_address:
            addr = signing_address.lower()
            if addr.startswith('0x'):
                addr = addr[2:]
            # Address is in the first 32 bytes, right-padded or left-padded
            first_32 = rd_hex[:64].lower()
            # Try both: address at start (left-aligned) or end (right-aligned, Ethereum-style)
            addr_match = addr in first_32
            result['address_matches'] = addr_match
            if not addr_match:
                checks_passed = False

        if nonce:
            nonce_hex = nonce
            if nonce_hex.startswith('0x'):
                nonce_hex = nonce_hex[2:]
            last_32 = rd_hex[64:128].lower()
            nonce_match = nonce_hex.lower() in last_32
            result['nonce_matches'] = nonce_match
            if not nonce_match:
                checks_passed = False

        result['valid'] = checks_passed

    except Exception as e:
        result['error'] = str(e)

    return result


def verify_with_dstack_service(
    quote_hex: str,
    event_log: str = '',
    vm_config: str = '',
    app_compose: dict | None = None,
) -> DstackVerification:
    """Verify attestation using dstack-verifier Docker service at localhost:8080.

    Sends quote + event_log + vm_config for full event log replay verification.
    Falls back gracefully if service is not running.
    """
    dv = DstackVerification()

    try:
        raw_hex = quote_hex
        if raw_hex.startswith('0x'):
            raw_hex = raw_hex[2:]

        payload = json.dumps({
            'quote': raw_hex,
            'event_log': event_log,
            'vm_config': vm_config,
        }).encode()

        req = urllib.request.Request(
            'http://localhost:8080/verify',
            data=payload,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'dstack-audit/1.0',
            },
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())

        dv.verified = True

        # Parse verification results per component
        # dstack-verifier returns structured results
        if isinstance(data, dict):
            dv.app_valid = data.get('app_valid', False)
            dv.kms_valid = data.get('kms_valid', False)
            dv.gateway_valid = data.get('gateway_valid', False)

            # Check compose hash if app_compose provided
            if app_compose:
                compose_hash = compute_compose_hash(app_compose)
                verified_hash = data.get('compose_hash', '')
                dv.compose_verified = (compose_hash == verified_hash)

    except urllib.error.URLError:
        dv.error = "dstack-verifier service not running at localhost:8080"
    except Exception as e:
        dv.error = f"dstack-verifier error: {e}"

    return dv
