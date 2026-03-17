# [Project Name] — TEE Trust Report

**Project**: [URL]
**Date**: [Date]
**Auditor**: [Name/Agent]

## One-Glance Card

**Verdict:** [SAFE / PARTIAL / NOT SAFE] — [one-line reason]

| Dimension | Status | Signal | Evidence |
|-----------|--------|--------|----------|
| Operator gap (can operator exfiltrate?) | PASS/FAIL/PARTIAL | GREEN/YELLOW/RED | [allowed_envs, ${VAR} URLs] |
| Attestation integrity | PASS/FAIL/PARTIAL | GREEN/YELLOW/RED | [TDX quote + compose_hash match] |
| TLS binding | PASS/FAIL/PARTIAL | GREEN/YELLOW/RED | [certFingerprint vs attestation] |
| Build reproducibility | PASS/FAIL/PARTIAL | GREEN/YELLOW/RED | [digest pin + SOURCE_DATE_EPOCH] |
| Upgrade transparency | PASS/FAIL/PARTIAL | GREEN/YELLOW/RED | [Base KMS / timelock / history] |

Signal key: GREEN=closed, YELLOW=partial/unknown, RED=attackable

## Summary

| Item | Result | Notes |
|------|--------|-------|
| Verdict | SAFE / PARTIAL / NOT SAFE | One sentence |
| Stage | Unproven / Stage 0 / Stage 1 candidate | Why |
| Website | PASS / WARN / FAIL | TLS and live evidence |
| Repo | PASS / WARN / FAIL | Auditability and reproducibility |

## Executive Summary

[2-3 sentence summary of findings]

---

## Deployment Data

| Field | Value | Verified |
|-------|-------|----------|
| App ID | `xxx` | ✅/❌ |
| Compose Hash | `xxx` | ✅/❌ |
| Docker Image | `xxx@sha256:xxx` | ✅/❌ |
| Source Commit | `xxx` | ✅/❌ |

---

## Critical Issues

### 1. [Issue Title]

**Severity**: CRITICAL
**File**: `path/to/file.py:line`

**Problem**:
[Description of the vulnerability]

**Code**:
```python
# Vulnerable code snippet
```

**Attack Vector**:
[How an attacker/operator could exploit this]

**Impact**:
[What's compromised - data exfiltration, integrity, etc.]

**Recommendation**:
[Specific fix]

---

## High Priority Issues

### 2. [Issue Title]

**Severity**: HIGH
**File**: `path/to/file.py:line`

[Same format as Critical]

---

## Medium Priority Issues

### 3. [Issue Title]

**Severity**: MEDIUM
**File**: `path/to/file.py:line`

[Same format]

---

## What's Done Well

- [Positive finding 1]
- [Positive finding 2]
- [Positive finding 3]

---

## Data Flow Diagram

```
User → [Entry Point] → [Processing]
                           ↓
                    [External Service] ← ⚠️ [TRUST BOUNDARY]
                           ↓
                      [Storage]
```

[Annotate with trust boundaries and configurable endpoints]

---

## Trust Model Analysis

| Component | Trusted By | Protects Against | Does NOT Protect Against |
|-----------|------------|------------------|--------------------------|
| TEE (TDX) | User | Cloud provider | Operator |
| dstack | User | Side channels | Malicious compose |
| [Service] | Code | [What] | [What] |

---

## Verification Checklist

| Check | Status | Evidence |
|-------|--------|----------|
| Source code public | ✅/❌ | [Link] |
| Docker image public | ✅/❌ | [Link] |
| Build reproducible | ✅/❌ | [How verified] |
| Critical URLs hardcoded | ✅/❌ | [Which file] |
| Attestation at startup | ✅/❌ | [Code location] |
| Per-request verification | ✅/❌ | [Code location] |
| Secrets in KMS | ✅/❌ | [How] |
| Contracts verified | ✅/❌/N/A | [Explorer link] |

---

## Recommendations

### Immediate (Critical)

1. [Action item with specific file/line changes]

### High Priority

2. [Action item]
3. [Action item]

### Medium Priority

4. [Action item]
5. [Action item]

---

## Open Questions

- [Question for project team]
- [Clarification needed]

---

## Verification Status

| Check | Status | Notes |
|-------|--------|-------|
| Compose hash | Verified / Not checked | [detail] |
| TDX quote | Verified / NOT VERIFIED | [tool used or why not] |
| TLS binding | Strong / Partial / None | [detail] |
| Image-to-source | Traced / Unverifiable | [detail] |
| Reproducible build | Verified / Not attempted | [detail] |
| On-chain history | Queried / Not available | [detail] |

## Recommended Next Step

[The single highest-leverage change to move closer to Stage 1. Be specific.]

---

## Appendix: Files Reviewed

| File | Purpose | Concerns |
|------|---------|----------|
| `src/main.py` | Entry point | None |
| `src/config.py` | Settings | URL configurable |
| `docker-compose.yml` | Deployment | [Issue] |
