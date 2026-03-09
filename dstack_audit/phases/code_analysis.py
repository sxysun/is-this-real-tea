"""Phase 4: Grep-based vulnerability scan of the GitHub repo."""
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from ..models import CodeAnalysisResult


def load_search_patterns(patterns_path: str | None = None) -> dict:
    """Load grep patterns from search_patterns.json."""
    if patterns_path is None:
        patterns_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'patterns', 'search_patterns.json'
        )
    with open(patterns_path) as f:
        return json.load(f)


def clone_repo(repo_url: str, dest: str | None = None) -> str:
    """Clone a GitHub repo to a temporary directory. Returns path."""
    if dest is None:
        dest = tempfile.mkdtemp(prefix='dstack-audit-')

    # Handle both https and git@ URLs
    subprocess.run(
        ['git', 'clone', '--depth', '1', repo_url, dest],
        capture_output=True, text=True, timeout=120, check=True
    )
    return dest


def grep_repo(repo_path: str, pattern: str, glob_filter: str = '') -> list[dict]:
    """Run grep on a repo and return matches."""
    cmd = ['grep', '-rn', '-E', pattern, repo_path]
    if glob_filter:
        cmd = ['grep', '-rn', '-E', f'--include={glob_filter}', pattern, repo_path]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        matches = []
        for line in result.stdout.strip().splitlines():
            if not line:
                continue
            # Format: file:line_num:content
            parts = line.split(':', 2)
            if len(parts) >= 3:
                file_path = parts[0].replace(repo_path + '/', '', 1)
                # Skip common non-source files
                if _should_skip(file_path):
                    continue
                matches.append({
                    'file': file_path,
                    'line': parts[1],
                    'content': parts[2].strip(),
                })
        return matches
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return []


def _should_skip(file_path: str) -> bool:
    """Skip binary/vendored/generated files."""
    skip_dirs = {
        'node_modules', '.git', 'vendor', 'dist', 'build',
        '__pycache__', '.next', 'target', 'pkg',
    }
    skip_exts = {
        '.min.js', '.map', '.lock', '.sum', '.png', '.jpg',
        '.ico', '.woff', '.ttf', '.svg', '.pyc',
    }
    parts = Path(file_path).parts
    if any(d in skip_dirs for d in parts):
        return True
    if any(file_path.endswith(ext) for ext in skip_exts):
        return True
    return False


def analyze_code(repo_path: str, patterns: dict | None = None) -> CodeAnalysisResult:
    """Run all code analysis patterns against a cloned repo."""
    if patterns is None:
        patterns = load_search_patterns()

    result = CodeAnalysisResult(repo_path=repo_path)

    for category, category_patterns in patterns.items():
        matches = []
        for pat_info in category_patterns:
            pattern = pat_info['pattern']
            glob_filter = pat_info.get('glob', '')
            found = grep_repo(repo_path, pattern, glob_filter)
            for m in found:
                m['pattern_name'] = pat_info.get('name', pattern)
                m['description'] = pat_info.get('description', '')
            matches.extend(found)

        # Deduplicate by file:line
        seen = set()
        deduped = []
        for m in matches:
            key = f"{m['file']}:{m['line']}"
            if key not in seen:
                seen.add(key)
                deduped.append(m)

        if hasattr(result, category):
            setattr(result, category, deduped)

    return result
