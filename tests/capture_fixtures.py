#!/usr/bin/env python3
"""Capture fixture data from live Phala Cloud endpoints.

Usage: python capture_fixtures.py [case_name]

Fetches 8090 HTML responses and saves them to fixtures/ for offline testing.
"""
import json
import os
import sys
import urllib.request

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')

ENDPOINTS = {
    'hermes': {
        'app_id': 'db82f5',
        'cluster': 'dstack-pha-prod9',
    },
    'tee-totalled': {
        'app_id': '4e0b5429671d8f90198c806f93e3c0a483f64cff',
        'cluster': 'dstack-pha-prod7',
    },
    'tokscope-xordi': {
        'app_id': 'f44389',
        'cluster': 'dstack-pha-prod9',
    },
    'xordi-toy-example': {
        'app_id': 'f9d35f',
        'cluster': 'dstack-base-prod9',
    },
    'firecrawl': {
        'app_id': 'ab8511',
        'cluster': 'dstack-pha-prod7',
    },
}


def capture(name: str, endpoint: dict):
    app_id = endpoint['app_id']
    cluster = endpoint['cluster']

    fixture_dir = os.path.join(FIXTURES_DIR, name)
    os.makedirs(fixture_dir, exist_ok=True)

    # Fetch 8090 HTML
    url = f"https://{app_id}-8090.{cluster}.phala.network/"
    print(f"Fetching {url}...")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'dstack-audit/1.0'})
        with urllib.request.urlopen(req, timeout=30) as resp:
            html = resp.read().decode('utf-8')
        with open(os.path.join(fixture_dir, '8090.html'), 'w') as f:
            f.write(html)
        print(f"  Saved 8090.html ({len(html)} bytes)")
    except Exception as e:
        print(f"  Failed: {e}")

    # Fetch Cloud API attestation
    api_url = f"https://cloud-api.phala.network/api/v1/apps/{app_id}/attestations"
    print(f"Fetching {api_url}...")
    try:
        req = urllib.request.Request(api_url, headers={'User-Agent': 'dstack-audit/1.0'})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        with open(os.path.join(fixture_dir, 'cloud_api.json'), 'w') as f:
            json.dump(data, f, indent=2)
        print(f"  Saved cloud_api.json")
    except Exception as e:
        print(f"  Failed: {e}")


def main():
    targets = sys.argv[1:] if len(sys.argv) > 1 else ENDPOINTS.keys()
    for name in targets:
        if name not in ENDPOINTS:
            print(f"Unknown case: {name}")
            continue
        print(f"\n=== {name} ===")
        capture(name, ENDPOINTS[name])


if __name__ == '__main__':
    main()
