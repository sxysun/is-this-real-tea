Perform a comprehensive security audit of a dstack/Phala TEE application.

Arguments: $ARGUMENTS

Parse the arguments from $ARGUMENTS. The user may provide any combination of:
- A **GitHub repo URL** (required) — the source code to audit
- A **deployment URL** — could be a Phala Cloud gateway URL, a custom domain, or any endpoint
- An **attestation source** — could be:
  - A Phala Cloud 8090 URL (e.g., `https://{app_id}-8090.{cluster}.phala.network/`)
  - A Trust Center URL (e.g., `https://trust.phala.com/app/{app_id}`)
  - A Phala Cloud API URL (e.g., `https://cloud-api.phala.network/api/v1/apps/{app_id}/attestations`)
  - A local file path containing attestation JSON or 8090 HTML
  - An app's `/attestation` endpoint
  - Nothing — the user may not have attestation data yet

If only a repo URL is given, do code-only analysis. If the user provides additional URLs or files, use them.

## Phase 1: Gather Deployment Data

Try to collect attestation and deployment data from whatever sources are available. Adapt to what works:

### Option A: Phala Cloud gateway URL provided
1. Parse `https://{app_id}-{port}[s].{cluster}.phala.network/` to extract app_id and cluster
2. Try the 8090 metadata endpoint: `curl -s "https://{app_id}-8090.{cluster}.phala.network/"`
3. If 8090 fails, try the Phala Cloud API: `curl -s "https://cloud-api.phala.network/api/v1/apps/{app_id}/attestations"`
4. Try the app's own `/attestation` endpoint for TLS binding data

### Option B: Custom domain provided
1. Look up `_dstack-app-address` DNS TXT record to find the Phala gateway URL
2. Then follow Option A

### Option C: Attestation data provided directly
1. If the user provides a Trust Center URL, Cloud API URL, local file, or pastes attestation JSON, use that
2. Extract what you can: app_compose, compose_hash, TDX quote, allowed_envs

### Option D: No deployment data
1. Do code-only analysis (Phase 2)
2. Note which checks couldn't be performed without live data

From whatever source, try to extract:
- `app_compose` JSON (contains `docker_compose_file`, `allowed_envs`, `kms_enabled`, `pre_launch_script`)
- Compose hash
- TDX quote presence and content
- TLS certificate fingerprint and attested fingerprint
- Docker image references from the deployed compose

## Phase 2: Clone and Analyze the Source Code

Clone the repo. Then perform deep analysis across these areas:

### 2a. Configuration Control (MOST CRITICAL)

The core question: **Can the operator exfiltrate user data?**

- Search for ALL external URLs in the codebase (`*_URL`, `base_url`, `endpoint`, `*_API*`)
- For EACH URL found, trace the data flow:
  - What user data does it receive?
  - Is it hardcoded in docker-compose.yml or configurable via `${VAR}`?
  - Is it in `allowed_envs`?
- Read the actual code at each location — understand what data flows through it
- A URL is only dangerous if user data passes through it. Config URLs for non-sensitive data are OK.

Show the vulnerable code with file:line references and explain the attack vector.

### 2b. Attestation Verification

- Find attestation/verification code
- Check if the signing key is cryptographically bound to the TDX quote's report_data
- Look for "known issue" comments near verification code (hash mismatch acceptance)
- Check what happens when attestation fails — hard fail or dev fallback?
- Check for development mode fallbacks (`is_development`, `dev_mode`, `fallback`, `mock`)

### 2c. Build Reproducibility

- Check Dockerfiles for pinned base images (`FROM image@sha256:...`)
- Look for `SOURCE_DATE_EPOCH`
- Check for `apt-get update` without snapshot pinning
- Check CI/CD for `--rewrite-timestamp` in buildx
- Check for lockfiles (package-lock.json, poetry.lock, etc.)

### 2d. Data Flow & Storage

- Trace user input from entry point through processing to external services
- Identify what data is persisted and where
- Check if sensitive data is encrypted at rest
- Map all external services that receive user data

### 2e. Smart Contracts (if applicable)

- Find contract addresses in the code
- Check if AppAuth is used
- Note which chain
- Check for timelock on upgrades

## Phase 3: Build Reproducibility Verification

If the repo has a Dockerfile, attempt to verify the build is reproducible:

1. **Check if the repo has reproducibility infrastructure**:
   - Look for `build-reproducible.sh`, `build-deterministic.sh`, or similar
   - Check Dockerfiles for `SOURCE_DATE_EPOCH`, `--chmod=644`, `rewrite-timestamp`
   - Check CI workflows for reproducible build steps

2. **If reproducibility infra exists, try building**:
   ```bash
   # Build twice with --no-cache, compare hashes
   docker buildx build \
     --build-arg SOURCE_DATE_EPOCH=0 \
     --no-cache \
     --output type=oci,dest=build1.tar,rewrite-timestamp=true \
     .
   docker buildx build \
     --build-arg SOURCE_DATE_EPOCH=0 \
     --no-cache \
     --output type=oci,dest=build2.tar,rewrite-timestamp=true \
     .
   # Compare: sha256sum build1.tar build2.tar
   ```

3. **If deployment data is available, compare against deployed digest**:
   - Extract image references from the deployed `docker_compose_file`
   - If images are pinned by `@sha256:`, pull them and compare layer hashes against your local build
   - Use `skopeo inspect` to get the deployed image digest
   - Compare: does your rebuild from source produce the same digest?

4. **Report the result**:
   - REPRODUCIBLE: local double-build matches, and (if applicable) matches deployed digest
   - PARTIALLY REPRODUCIBLE: double-build matches but can't verify against deployment
   - NOT REPRODUCIBLE: double-build produces different hashes (explain which layer differs)
   - NOT ATTEMPTED: no Dockerfile or reproducibility infra found

## Phase 4: Cross-Reference (if live deployment data available)

- Compare the deployed `docker_compose_file` from app_compose against compose files in the repo
- Check if deployed images match what the repo builds
- Map `allowed_envs` against actual environment variable usage in code
- Flag any `${VAR}` image references
- If Phase 3 produced a local build, compare its digest against the deployed image digest

## Phase 5: Generate Report

Structure the report as follows:

```
## Executive Summary

[2-3 sentences: what the app does, key findings, overall verdict]

| Component | Status | Notes |
|-----------|--------|-------|
| Configuration Control | [status] | [note] |
| Attestation & TLS | [status] | [note] |
| Build Reproducibility | [status] | [note] |
| Data Flow & Storage | [status] | [note] |
| On-chain / KMS | [status] | [note] |

## Deployment Data

[app_id, compose_hash, images, KMS type, TDX status — if available]

## Critical Issues

For each critical finding:
- **Severity** and **File:Line**
- The actual vulnerable code (quoted from source)
- **Attack Vector**: What a malicious operator could do, step by step
- **Impact**: What gets compromised
- **Fix**: Specific code change

## Architecture & Data Flow

[ASCII diagram showing data flow with trust boundaries annotated]

## Attestation Analysis

[Detailed analysis of attestation code, binding verification, fallback paths]

## Build Reproducibility

[What's pinned, what's not, can you reproduce the image?]
[If you attempted a build in Phase 3, report: double-build result, deployed digest comparison]
[If the image digest from your local build matches the deployed digest, state this explicitly — it's strong evidence]
[If it doesn't match, investigate: which layer differs? Is it a timestamp issue or real divergence?]

## What's Done Well

[Positive findings — things the project got right]

## Verification Checklist

| Check | Status | Evidence |
|-------|--------|----------|
| Source code public | | |
| Docker image public | | |
| Build reproducible | | |
| Build reproduced locally | | |
| Deployed digest matches rebuild | | |
| Critical URLs hardcoded | | |
| TDX quote present | | |
| Signing key bound to quote | | |
| No dev fallbacks in prod | | |
| KMS keys (not operator) | | |
| AppAuth contract | | |
| Upgrade timelock | | |

## Stage Assessment

Assess against ERC-733:

**Stage 0 (Ruggable)** if ANY of:
- No TDX quote
- Pha KMS without on-chain AppAuth (no public upgrade log)
- Mutable image tags (no @sha256: pinning)
- Configurable URLs that handle user data
- Instant upgrades (no timelock)

**Stage 1 (DevProof)** requires ALL of:
- On-chain KMS with AppAuth
- Pinned image digests
- Timelock on upgrades
- No configurable exfiltration vectors
- TLS binding verified
- Reproducible builds

## Recommendations

### Immediate (Critical)
[Specific fixes with file paths]

### High Priority
[Important improvements]

### For Stage 1
[What would need to change]
```

## Quick automated scan first

Before deep analysis, run the automated checker:
```bash
./tools/audit-checks.sh /path/to/repo
```

If you have an app_id, verify the compose hash:
```bash
python3 tools/verify-compose-hash.py <app-id> [cluster]
```

## Reference files

Consult these during the audit:
- `references/devproof-stages.md` — stage criteria (Unproven / Stage 0 / Stage 1)
- `references/live-checks.md` — endpoint heuristics, TLS binding classification
- `references/case-studies.md` — patterns from real audits
- `references/search-patterns.md` — grep patterns for common vulnerabilities
- `references/STAGE-1-CHECKLIST.md` — ERC-733 Stage 1 requirements
- `references/report-template.md` — one-glance card + report structure

## Important Notes

- **Read the actual code**. Don't just report grep matches. Understand what each finding means.
- **Trace data flows**. A configurable URL is only critical if user data flows through it.
- **Quote specific code** with file:line references.
- **Explain attack vectors** as step-by-step scenarios a malicious operator could execute.
- **Note what's done well**. Good security practices deserve recognition.
- **No silent assumptions.** If you can't verify something, say so explicitly. "TDX quote: NOT VERIFIED" is an honest finding.
