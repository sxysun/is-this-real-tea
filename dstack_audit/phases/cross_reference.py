"""Phase 5: Cross-reference deployed config against source repo."""
import os
import re

from ..models import CrossReferenceResult, Finding, Severity


def find_compose_files(repo_path: str) -> list[str]:
    """Find docker-compose files in the repo."""
    candidates = [
        'docker-compose.yml',
        'docker-compose.yaml',
        'compose.yml',
        'compose.yaml',
    ]
    found = []
    for root, dirs, files in os.walk(repo_path):
        # Skip hidden dirs and common non-source dirs
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                    ('node_modules', 'vendor', 'dist', 'build', 'target')]
        for f in files:
            if f in candidates:
                found.append(os.path.join(root, f))
    return found


def normalize_compose(text: str) -> str:
    """Normalize whitespace for comparison."""
    lines = []
    for line in text.splitlines():
        stripped = line.rstrip()
        if stripped:
            lines.append(stripped)
    return '\n'.join(lines)


def extract_images_from_compose(compose_text: str) -> list[str]:
    """Extract image references from a docker-compose file."""
    images = []
    for match in re.finditer(r'image:\s*["\']?([^\s"\'#]+)', compose_text):
        images.append(match.group(1))
    return images


def cross_reference(
    deployed_compose: str,
    allowed_envs: list[str],
    repo_path: str,
    code_analysis_results: dict | None = None,
) -> tuple[CrossReferenceResult, list[Finding]]:
    """Compare deployed config against source repo.

    Args:
        deployed_compose: docker_compose_file from app_compose
        allowed_envs: allowed_envs from app_compose
        repo_path: path to cloned repo
        code_analysis_results: optional results from Phase 4
    """
    result = CrossReferenceResult()
    findings = []

    # 1. Compare deployed compose against repo compose files
    repo_composes = find_compose_files(repo_path)
    if repo_composes:
        deployed_norm = normalize_compose(deployed_compose)
        best_match = None
        best_score = 0
        for path in repo_composes:
            with open(path) as f:
                repo_norm = normalize_compose(f.read())
            # Simple line-based similarity
            deployed_lines = set(deployed_norm.splitlines())
            repo_lines = set(repo_norm.splitlines())
            if not deployed_lines:
                continue
            overlap = len(deployed_lines & repo_lines)
            score = overlap / max(len(deployed_lines), len(repo_lines))
            if score > best_score:
                best_score = score
                best_match = path

        if best_score > 0.8:
            result.compose_match = True
            result.compose_diff_summary = (
                f"Deployed compose matches {os.path.relpath(best_match, repo_path)} "
                f"({best_score:.0%} similarity)"
            )
        elif best_match:
            result.compose_match = False
            result.compose_diff_summary = (
                f"Best match: {os.path.relpath(best_match, repo_path)} "
                f"({best_score:.0%} similarity) - significant differences"
            )
            findings.append(Finding(
                phase="cross_reference",
                severity=Severity.WARNING,
                title="Deployed compose differs from repo",
                detail=result.compose_diff_summary,
                category="compose_mismatch",
            ))
    else:
        result.compose_match = None
        result.compose_diff_summary = "No docker-compose files found in repo"

    # 2. Check deployed images
    deployed_images = extract_images_from_compose(deployed_compose)
    for img in deployed_images:
        if '${' in img:
            result.image_issues.append(f"Variable image reference: {img}")
            findings.append(Finding(
                phase="cross_reference",
                severity=Severity.CRITICAL,
                title="Variable image reference in deployed compose",
                detail=(
                    f"Image `{img}` uses a variable substitution. "
                    f"The actual image is determined by allowed_envs at runtime, "
                    f"making it impossible to audit the deployed code."
                ),
                category="variable_image",
            ))
        elif '@sha256:' not in img:
            result.image_issues.append(f"Mutable image tag: {img}")
            findings.append(Finding(
                phase="cross_reference",
                severity=Severity.CRITICAL,
                title="Mutable image tag (not pinned by digest)",
                detail=(
                    f"Image `{img}` uses a mutable tag. "
                    f"The image content can change without updating the compose hash."
                ),
                category="mutable_image",
            ))

    # 3. Check allowed_envs for exfiltration vectors
    url_env_patterns = re.compile(
        r'(URL|ENDPOINT|HOST|SERVER|GATEWAY|BASE|API|WEBHOOK|CALLBACK|REDIRECT)',
        re.IGNORECASE
    )
    for env in allowed_envs:
        if url_env_patterns.search(env):
            result.env_issues.append(f"Configurable URL env: {env}")
            findings.append(Finding(
                phase="cross_reference",
                severity=Severity.CRITICAL,
                title=f"Configurable URL in allowed_envs: {env}",
                detail=(
                    f"Environment variable `{env}` appears to configure a URL/endpoint. "
                    f"Since allowed_envs can be changed at runtime without changing the "
                    f"compose hash, this could be used to redirect data to an attacker-"
                    f"controlled server."
                ),
                category="configurable_url",
            ))

    # 4. Check for ${VAR} references in allowed_envs that affect images
    for env in allowed_envs:
        for img in deployed_images:
            if f'${{{env}}}' in img or f'${env}' in img:
                result.image_issues.append(
                    f"allowed_env `{env}` controls image: {img}"
                )
                # Already flagged as variable_image above

    return result, findings
