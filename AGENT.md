# TEE Security Audit -- Agent Instructions

You are about to audit a dstack/Phala TEE application for production safety. Follow these instructions to determine whether the app is safe for users to interact with.

**You need**: a GitHub repo URL (required), and optionally a deployment URL or attestation data.

---

## Quick version

If you're short on time, focus on these three things:

1. **Clone the repo and read `docker-compose.yml`** -- find every `${VAR}` pattern. For each one, check if user data flows through that variable. If yes, the operator can exfiltrate that data. **This is the most common critical vulnerability.**

2. **Search for attestation code** -- grep for `attestation`, `tdx`, `quote`, `dstack-sdk`, `getKey`. If there's nothing, the TEE is decorative. If there's code, check if verification is enforced or just logged.

3. **Check Dockerfiles for `FROM image@sha256:`** -- if base images aren't pinned by digest, builds aren't reproducible and the deployed code can't be verified.

Any of these failing = **Stage 0 (Ruggable)**. Report what you find.

---

## Full audit methodology

### Phase 1: Gather deployment data

If the user provided a deployment URL, try to fetch attestation data. Adapt to what's available:

**Phala Cloud gateway URL** (format: `https://{app_id}-{port}[s].{cluster}.phala.network/`):
```bash
# Extract app_id from the URL, try the 8090 metadata endpoint
curl -s "https://{app_id}-8090.{cluster}.phala.network/"

# If 8090 fails, try the Cloud API
curl -s "https://cloud-api.phala.network/api/v1/apps/{app_id}/attestations"

# Try the app's own attestation endpoint
curl -s "https://{deployment_url}/attestation"
```

**Custom domain**: look up `_dstack-app-address` DNS TXT record to find the gateway URL, then follow above.

**No deployment URL**: do code-only analysis. Note which checks couldn't be performed.

From whatever source, try to extract:
- `app_compose` JSON (contains `docker_compose_file`, `allowed_envs`, `kms_enabled`, `pre_launch_script`)
- Compose hash
- TDX quote (empty = `--dev-os`, no TEE guarantees)
- TLS certificate fingerprint
- Docker image references from the deployed compose

### Phase 2: Analyze the source code

Clone the repo and perform deep analysis. **Read the actual code -- don't just grep.**

#### 2a. Configuration control (MOST CRITICAL)

The core question: **can the operator exfiltrate user data?**

In dstack, operators control `allowed_envs` -- environment variables injected at runtime without changing the compose hash. If a URL handling user data is configurable via env var, the operator can redirect it to their own server and steal everything.

Do this:
1. Search for ALL external URLs in the codebase: `*_URL`, `base_url`, `endpoint`, `*_API*`, `fetch(`, `axios(`, `requests.`
2. For EACH URL found, answer:
   - What user data does it receive? (trace the actual data flow in code)
   - Is it hardcoded in docker-compose.yml or configurable via `${VAR}`?
   - Is it listed in `allowed_envs`?
3. A URL is only dangerous if user data passes through it. Config for non-sensitive data is OK.
4. Show the vulnerable code with file:line references and explain the attack vector.

**Example of a critical finding:**
```
CRITICAL: LLM_BASE_URL is operator-configurable

File: src/config.py:28
  base_url = os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1")

File: docker-compose.yml:12
  - LLM_BASE_URL=${LLM_BASE_URL}

Attack vector:
1. Operator sets LLM_BASE_URL to https://evil-proxy.com/v1
2. All user prompts are sent to the operator's server
3. Compose hash doesn't change because LLM_BASE_URL is env-injected
4. Users see valid attestation but their data is being exfiltrated
```

#### 2b. Attestation verification

- Find attestation/verification code (search for `attestation`, `tdx`, `quote`, `report_data`, `dstack`, `getKey`)
- Check if the signing key is cryptographically bound to the TDX quote's `report_data`
- Look for "known issue" comments near verification code (hash mismatch acceptance, TODO notes)
- Check what happens when attestation fails -- hard fail or silent fallback?
- Search for development mode bypasses: `is_development`, `dev_mode`, `DEV`, `fallback`, `mock`, `DISABLE_VERIFY`

#### 2c. Build reproducibility

- Check Dockerfiles for pinned base images (`FROM image@sha256:...` not just `FROM image:tag`)
- Look for `SOURCE_DATE_EPOCH` in Dockerfile or CI
- Check for `apt-get update` without debian snapshot pinning (`snapshot.debian.org`)
- Check CI/CD workflows for `--rewrite-timestamp` in buildx commands
- Check for committed lockfiles (`package-lock.json`, `poetry.lock`, `uv.lock`, `Cargo.lock`)
- Look for `build-reproducible.sh` or similar scripts

#### 2d. Data flow and storage

- Trace user input from entry point through processing to all external services
- Identify what data is persisted and where (inside TEE? external database? cloud service?)
- Check if sensitive data is encrypted before leaving the TEE boundary
- Map every external service that receives user data
- Data sent to services outside the TEE is outside the trust boundary -- note this explicitly

#### 2e. Smart contracts (if applicable)

- Find contract addresses in the code
- Check if AppAuth is used (on-chain compose hash registry)
- Note which chain (Base, Ethereum, etc.)
- Check for timelock on upgrades (`getTimelock()`, `addComposeHash()`)

### Phase 3: Build reproducibility verification (optional)

If Docker is available and the repo has reproducibility infrastructure, try verifying:

```bash
# Build twice, compare hashes
docker buildx build --build-arg SOURCE_DATE_EPOCH=0 --no-cache \
  --output type=oci,dest=build1.tar,rewrite-timestamp=true .
docker buildx build --build-arg SOURCE_DATE_EPOCH=0 --no-cache \
  --output type=oci,dest=build2.tar,rewrite-timestamp=true .
sha256sum build1.tar build2.tar
# These should match
```

If deployment data is available, compare your local build digest against the deployed image digest using `skopeo inspect`.

### Phase 4: Cross-reference (if deployment data available)

- Compare the deployed `docker_compose_file` from attestation against compose files in the repo
- Check if deployed images match what the repo would build
- Map `allowed_envs` against actual environment variable usage in code
- Flag any `${VAR}` image references (operator can swap the entire container)

### Phase 5: Generate report

Structure your report like this:

```markdown
## Executive Summary

[2-3 sentences: what the app does, key findings, overall safety verdict]

| Component | Status | Notes |
|-----------|--------|-------|
| Configuration Control | pass/warn/fail | [brief note] |
| Attestation & TLS | pass/warn/fail | [brief note] |
| Build Reproducibility | pass/warn/fail | [brief note] |
| Data Flow & Storage | pass/warn/fail | [brief note] |
| On-chain / KMS | pass/warn/fail | [brief note] |

## Critical Issues

For each critical finding:
- **Severity** and **File:Line**
- The actual vulnerable code (quoted)
- **Attack Vector**: step-by-step what a malicious operator could do
- **Impact**: what gets compromised
- **Fix**: specific code change needed

## Architecture & Data Flow

[ASCII diagram showing user data flow, TEE boundary, and external services]

## Attestation Analysis

[Is there a TDX quote? Is the signing key bound? Any dev fallbacks?]

## Build Reproducibility

[Pinned images? SOURCE_DATE_EPOCH? Lockfiles? Can you reproduce the build?]

## What's Done Well

[Positive findings -- good security practices deserve recognition]

## Verification Checklist

| Check | Status | Evidence |
|-------|--------|----------|
| Source code public | | |
| Docker image pinned by digest | | |
| Build reproducible | | |
| Critical URLs hardcoded | | |
| TDX quote present | | |
| Signing key bound to quote | | |
| No dev fallbacks in prod | | |
| KMS keys (not operator-injected) | | |
| AppAuth contract | | |
| Upgrade timelock | | |

## Stage Assessment

**Stage 0 (Ruggable)** if ANY of:
- No TDX quote (empty = --dev-os)
- Pha KMS without on-chain AppAuth
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

### To reach Stage 1
[What would need to change]
```

---

## Important principles

- **Read the actual code.** Don't just report grep matches. Understand what each finding means in context.
- **Trace data flows.** A configurable URL is only critical if user data flows through it. Follow the code path.
- **Quote specific code** with file:line references so the reader can verify your findings.
- **Explain attack vectors** as step-by-step scenarios. "A malicious operator could..." not just "this is configurable."
- **Note what's done well.** Good security practices deserve recognition. Not everything is a finding.
- **Be honest about unknowns.** If you couldn't verify something (e.g., no deployment data), say so explicitly.

---

## Background: dstack TEE threat model

[dstack](https://github.com/Dstack-TEE/dstack) runs Docker containers inside Intel TDX (Trust Domain Extensions) hardware enclaves on Phala Network. The TEE protects running code from the cloud provider and host OS.

**What TEE protects against**: cloud provider reading memory, host OS tampering with execution, physical access attacks.

**What TEE does NOT protect against**: the application operator. The operator chooses which code to deploy, which env vars to inject, and which images to run. If the code has configurable exfiltration vectors, the TEE hardware faithfully executes the exfiltration.

The [ERC-733](https://draftv4.erc733.org) framework defines stages of trust:
- **Stage 0**: TEE is running but operator can still rug users
- **Stage 1 (DevProof)**: Cryptographically verifiable that the operator cannot exfiltrate data or push silent updates
- **Stage 2**: No single party controls upgrades (multi-party governance)
- **Stage 3**: Trustless (multi-vendor cross-attestation, ZK proofs)

Key dstack concepts:
- **compose hash**: `sha256` of the canonical JSON app_compose. Attested by the TDX quote. Changes when the docker-compose changes.
- **allowed_envs**: env vars the operator can set WITHOUT changing the compose hash. This is the primary attack surface.
- **8090 endpoint**: tappd metadata page at `{app_id}-8090.{cluster}.phala.network/` exposing the full `app_compose` including `docker_compose_file`, `allowed_envs`, TDX quote.
- **KMS**: Key Management Service. "Pha KMS" = Phala-managed keys (operator trusts Phala). "Base KMS" = on-chain key management with AppAuth contract (transparent).
- **AppAuth**: on-chain contract that records allowed compose hashes. Upgrades require `addComposeHash()` which can have a timelock.
