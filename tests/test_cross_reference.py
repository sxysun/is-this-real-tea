"""Tests for Phase 5: Cross-reference."""
import os
import tempfile
import pytest
from dstack_audit.phases.cross_reference import (
    cross_reference, extract_images_from_compose,
    find_compose_files, normalize_compose,
)
from dstack_audit.models import Severity


@pytest.fixture
def repo_with_compose():
    tmpdir = tempfile.mkdtemp(prefix='dstack-audit-xref-')
    compose_content = '''version: '3'
services:
  app:
    image: myapp:latest
    ports:
      - "3000:3000"
'''
    with open(os.path.join(tmpdir, 'docker-compose.yaml'), 'w') as f:
        f.write(compose_content)
    yield tmpdir, compose_content
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)


class TestExtractImages:
    def test_simple_image(self):
        images = extract_images_from_compose("image: nginx:latest")
        assert images == ["nginx:latest"]

    def test_multiple_images(self):
        compose = '''services:
  web:
    image: nginx:1.25
  api:
    image: node:22@sha256:abc123
'''
        images = extract_images_from_compose(compose)
        assert len(images) == 2
        assert "nginx:1.25" in images
        assert "node:22@sha256:abc123" in images

    def test_variable_image(self):
        images = extract_images_from_compose("image: ${WORKER_IMAGE}")
        assert images == ["${WORKER_IMAGE}"]

    def test_quoted_image(self):
        images = extract_images_from_compose('image: "nginx:latest"')
        assert images == ["nginx:latest"]


class TestCrossReference:
    def test_matching_compose(self, repo_with_compose):
        tmpdir, compose_content = repo_with_compose
        result, findings = cross_reference(
            deployed_compose=compose_content,
            allowed_envs=[],
            repo_path=tmpdir,
        )
        assert result.compose_match is True

    def test_mutable_image_flagged(self, repo_with_compose):
        tmpdir, _ = repo_with_compose
        result, findings = cross_reference(
            deployed_compose="services:\n  app:\n    image: myapp:latest\n",
            allowed_envs=[],
            repo_path=tmpdir,
        )
        assert any(f.category == 'mutable_image' for f in findings)

    def test_variable_image_flagged(self, repo_with_compose):
        tmpdir, _ = repo_with_compose
        result, findings = cross_reference(
            deployed_compose="services:\n  app:\n    image: ${APP_IMAGE}\n",
            allowed_envs=['APP_IMAGE'],
            repo_path=tmpdir,
        )
        assert any(f.category == 'variable_image' for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_configurable_url_env_flagged(self, repo_with_compose):
        tmpdir, _ = repo_with_compose
        result, findings = cross_reference(
            deployed_compose="services:\n  app:\n    image: myapp@sha256:" + "a" * 64 + "\n",
            allowed_envs=['LLM_BASE_URL', 'LOG_LEVEL'],
            repo_path=tmpdir,
        )
        # LLM_BASE_URL should be flagged, LOG_LEVEL should not
        url_findings = [f for f in findings if f.category == 'configurable_url']
        assert len(url_findings) == 1
        assert 'LLM_BASE_URL' in url_findings[0].title

    def test_pinned_image_not_flagged(self, repo_with_compose):
        tmpdir, _ = repo_with_compose
        result, findings = cross_reference(
            deployed_compose="services:\n  app:\n    image: myapp@sha256:" + "a" * 64 + "\n",
            allowed_envs=[],
            repo_path=tmpdir,
        )
        image_findings = [f for f in findings if f.category in ('mutable_image', 'variable_image')]
        assert len(image_findings) == 0
