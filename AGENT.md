# TEE Security Audit -- Agent Instructions

You are checking whether a TEE (Trusted Execution Environment) app is actually safe to use, or just security theater.

The app runs inside tamper-proof hardware that the cloud provider can't read. But **the operator who deployed it might still be able to steal user data** -- unless the code is specifically set up to prevent this. Your job is to find out which case it is.

**You need**: a GitHub repo URL (required), and optionally a deployment URL or attestation data.

---

## Quick version

If you're short on time, check these four things:

1. **Read `docker-compose.yml` and find every `${VAR}` pattern.** For each one, trace whether user data flows through that variable. If it does, the operator can redirect that data to their own server. **This is the #1 vulnerability in TEE apps.**

2. **Search for attestation code** -- grep for `attestation`, `tdx`, `quote`, `dstack-sdk`, `getKey`, `rtmr`. If there's nothing, the TEE is decoration. The hardware can prove what code is running, but if the app never asks it to, the proof doesn't exist. If there is code, check whether verification is actually enforced or just logged and ignored. Also check if attestation data is available from ANY source (the app, 8090, Trust Center) -- the cryptographic proof is self-verifying regardless of where it comes from.

3. **Check Dockerfiles for `FROM image@sha256:`** -- if base images aren't pinned by exact hash, anyone could swap in different code and the builds can't be verified.

4. **If you have a deployment URL, verify the TLS certificate is bound to the TEE** -- connect to the site, get the cert fingerprint, compare it against what the app's `/attestation` endpoint claims. If they don't match (or there's no attestation endpoint), you can't prove your connection actually reaches the TEE.

If any of these fail, **the operator can still steal user data**. Report what you find.

---

## Full audit methodology

### Phase 1: Gather attestation data

Attestation is a cryptographic proof -- it doesn't matter where you get it from. You verify the proof itself, not the transport. Try any of these sources:

**From the user**: If they provide attestation data (JSON, a URL, a Trust Center link), use it directly. The data is self-verifying.

**From the app**: Many apps expose their own attestation endpoint:
```bash
curl -s "https://{deployment_url}/attestation"
curl -s "https://{deployment_url}/v1/attestation/report"
curl -s "https://{deployment_url}/.well-known/attestation"
```

**From Phala Cloud infrastructure**: If the app runs on Phala, you can also try:
```bash
# The 8090 metadata endpoint (if available)
curl -s "https://{app_id}-8090.{cluster}.phala.network/"

# The Cloud API
curl -s "https://cloud-api.phala.network/api/v1/apps/{app_id}/attestations"

# The Trust Center (shows verified attestation status)
# https://trust.phala.com/app/{app_id}
```

**From a custom domain**: look up `_dstack-app-address` DNS TXT record to find the app_id and cluster, then use the above.

**No attestation data at all**: do code-only analysis. Note which checks couldn't be performed.

**What to look for in the attestation data** (regardless of source):

The attestation contains cryptographic measurements that prove what code is running inside the TEE. Key fields:
- **RTMRs** (Runtime Measurement Registers: `mrtd`, `rtmr0`, `rtmr1`, `rtmr2`, `rtmr3`) -- hardware-generated hashes of the firmware, OS, and application layers. These are the core proof.
- **compose_hash** -- SHA-256 of the app's configuration. If the config changes, this changes.
- **TDX quote** -- a signed blob from Intel TDX hardware containing the RTMRs. If this is empty AND there are no RTMRs, the app may be running in dev mode with no real TEE protection.
- **event_log** -- a log of boot-time measurements that can be replayed to derive the RTMRs.
- **app_compose** -- the actual deployed configuration (contains `docker_compose_file`, `allowed_envs`, `kms_enabled`, `pre_launch_script`).

**Important**: RTMRs and event_log entries ARE attestation measurements even if the raw TDX quote blob isn't served at the endpoint you're looking at. The quote might be stored elsewhere (e.g., Trust Center) while the measurements derived from it are served at 8090 or the app's own endpoint. Don't conclude "no attestation" just because one field is empty -- check whether the measurements themselves are present.

### Phase 1b: Verify TLS binding (if deployment URL provided)

This proves you're actually talking to code inside the TEE, not a man-in-the-middle.

**How it works**: The app generates a TLS certificate inside the TEE, hashes it, and includes that hash in the hardware attestation. If the hash you see in the TLS connection matches what the hardware attests, the connection is proven to terminate inside the TEE.

**Step 1: Get the certificate fingerprint from the live TLS connection**
```bash
echo | openssl s_client -connect HOST:PORT 2>/dev/null | \
  openssl x509 -outform DER 2>/dev/null | shasum -a 256
```

**Step 2: Get the attested fingerprint from the app**
```bash
# Try common attestation endpoint paths
curl -sk https://HOST:PORT/attestation | python3 -c "import sys,json; print(json.load(sys.stdin).get('certFingerprint','NOT FOUND'))"

# If that fails, try:
# curl -sk https://HOST:PORT/v1/attestation/report
# curl -sk https://HOST:PORT/.well-known/attestation
# curl -sk https://HOST:PORT/quote
```

**Step 3: Compare**
- **Match** = the private key is proven to be inside the TEE. Connection is end-to-end secure.
- **Mismatch** = something is terminating TLS before the TEE. Could be a gateway or a MITM.
- **No attestation endpoint** = can't verify. Note this as a gap.

**Gateway-terminated vs end-to-end TLS**

Look at the URL:
- `{app_id}-443.cluster.phala.network` = **gateway-terminated**. The Phala gateway handles encryption, not the TEE directly. You're trusting the gateway infrastructure.
- `{app_id}-443s.cluster.phala.network` (note the **`s`**) = **end-to-end**. The TEE handles encryption directly. TLS binding verification works here.

If gateway-terminated, note: "TLS terminates at the gateway, not the TEE. Users trust Phala's gateway infrastructure in addition to the TEE."

### Phase 2: Analyze the source code

Clone the repo and perform deep analysis. **Read the actual code -- don't just grep.**

#### 2a. Can the operator steal user data? (MOST CRITICAL)

In dstack, operators can inject environment variables at deploy time without changing the attested code hash (via `allowed_envs`). If a URL that handles user data is controlled by an env var, the operator can silently redirect all user data to their own server.

Do this:
1. Search for ALL external URLs in the codebase: `*_URL`, `base_url`, `endpoint`, `*_API*`, `fetch(`, `axios(`, `requests.`
2. For EACH URL found, answer:
   - What user data does it receive? (trace the actual data flow in code)
   - Is it hardcoded in docker-compose.yml or configurable via `${VAR}`?
   - Is it listed in `allowed_envs`?
3. A URL is only dangerous if user data flows through it. Config URLs for non-sensitive data are fine.
4. Show the vulnerable code with file:line references and explain the attack.

**Example finding:**
```
CRITICAL: Operator can steal all user prompts

File: src/config.py:28
  base_url = os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1")

File: docker-compose.yml:12
  - LLM_BASE_URL=${LLM_BASE_URL}

Attack:
1. Operator sets LLM_BASE_URL to https://evil-proxy.com/v1
2. All user prompts are sent to the operator's server
3. The attested code hash doesn't change (env vars are outside it)
4. Users see valid attestation but their data is being stolen
```

#### 2b. Does the app actually use the TEE hardware?

The TEE hardware can generate cryptographic proof of what code is running. But if the app doesn't use this feature, the hardware protection is meaningless.

Search for:
- `attestation`, `tdx`, `quote`, `report_data`, `dstack`, `getKey`
- Check if found code actually enforces verification or just logs it
- Look for "known issue" comments, hash mismatch acceptance, TODO notes
- Check what happens when verification fails -- does the app stop, or silently continue?
- Search for dev mode bypasses: `is_development`, `dev_mode`, `DEV`, `fallback`, `mock`, `DISABLE_VERIFY`

#### 2c. Can you rebuild the code and get the same result?

If you can't reproduce the exact same image from source, you can't verify that what's deployed matches what's published. The operator could be running modified code.

Check:
- Dockerfiles: `FROM image@sha256:...` (exact hash) vs `FROM image:tag` (mutable, anyone can change what the tag points to)
- `SOURCE_DATE_EPOCH` in Dockerfile or CI (makes timestamps deterministic)
- `apt-get update` without debian snapshot pinning (pulls different packages on different days)
- CI/CD workflows for `--rewrite-timestamp` in buildx commands
- Committed lockfiles (`package-lock.json`, `poetry.lock`, `uv.lock`, `Cargo.lock`)
- Build scripts like `build-reproducible.sh`

#### 2d. Where does user data actually go?

- Trace user input from entry point through processing to all external services
- Identify what data is stored and where (inside TEE? external database? cloud service?)
- Data sent to services outside the TEE is no longer protected by the hardware -- note this explicitly
- Check if sensitive data is encrypted before leaving the TEE boundary
- Map every external service that receives user data

#### 2e. Can the operator push silent updates?

- Find contract addresses in the code (look for AppAuth, on-chain compose hash registry)
- Check if there's a timelock (waiting period before code changes take effect)
- Note which blockchain (Base, Ethereum, etc.)
- If there's no public upgrade log, the operator can swap the code at any time without anyone knowing

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

If deployment data is available, compare your local build hash against the deployed image hash using `skopeo inspect`.

### Phase 4: Cross-reference (if deployment data available)

- Compare the deployed docker-compose from attestation data against compose files in the repo
- Check if deployed images match what the repo would build
- Map `allowed_envs` against actual environment variable usage in code
- Flag any `${VAR}` image references (operator can swap the entire container without changing the code hash)

### Phase 5: Generate report

Structure your report like this:

```markdown
## Executive Summary

[2-3 sentences: what the app does, whether it's safe, and the key reason why or why not]

| Question | Answer |
|----------|--------|
| Can the operator steal user data? | yes/no/partially -- [how] |
| Is the TEE hardware actually proving anything? | yes/no -- [details] |
| Can you rebuild the code and verify it? | yes/no -- [details] |
| Where does user data go? | [list of destinations, which are inside/outside TEE] |
| Can the operator push silent updates? | yes/no -- [details] |

## Critical Issues

For each critical finding:
- **What's wrong** and **where** (file:line)
- The actual vulnerable code (quoted)
- **How the operator exploits this**: step-by-step
- **What gets stolen/compromised**
- **How to fix it**: specific code change

## Architecture & Data Flow

[ASCII diagram showing: user -> app -> external services, with the TEE boundary marked]

## Attestation Analysis

[Does the hardware actually prove anything? Is the TLS cert bound? Any dev mode bypasses?]

## Build Reproducibility

[Can you rebuild from source and get the same image? What's pinned, what's not?]

## What's Done Well

[Positive findings -- good practices deserve recognition]

## Verification Checklist

| Check | Status | Evidence |
|-------|--------|----------|
| Source code is public | | |
| Docker images pinned by exact hash | | |
| Builds are reproducible | | |
| All data-handling URLs are hardcoded (not configurable) | | |
| Hardware attestation is present (quote, RTMRs, or verified measurements) | | |
| TLS certificate is bound to attestation | | |
| TLS terminates in the TEE (not a gateway) | | |
| No dev mode fallbacks in production | | |
| Encryption keys come from TEE (not operator) | | |
| Code changes are publicly logged on-chain | | |
| Code changes have a waiting period (timelock) | | |

## Security Guarantees

Spell out exactly what this app protects against and what it doesn't. Be specific.

### What's protected
[List each protection with evidence. Examples:]
- "The cloud provider cannot read user data in memory" (TEE hardware, TDX quote present)
- "The deployed code matches the public repo" (image pinned by hash, build reproducible)
- "The TLS connection terminates inside the TEE" (cert fingerprint matches attestation)

### What attacks are still possible
[List each remaining attack with a concrete scenario. Examples:]
- "The operator can steal all user prompts by changing LLM_BASE_URL to their own proxy server (file:line). The attested code hash doesn't change because this is an env var."
- "The operator can push a new version of the code instantly with no public notice, because there's no upgrade timelock or on-chain registry."
- "Anyone who reads the source code can decrypt user cookies, because the fallback encryption key is hardcoded in the repo (file:line)."

### What can't be verified
[List things you couldn't check and why. Examples:]
- "Could not verify TLS binding because the attestation endpoint was unreachable"
- "Could not check if the deployed image matches the source because no deployment URL was provided"

## Recommendations

### The app is unsafe without these
[Specific fixes with file paths -- the attacks listed above]

### Important improvements
[Things that significantly reduce risk]

### To fully tie the operator's hands
[What would need to change so the operator provably cannot interfere]
```

---

## Important principles

- **Read the actual code.** Don't just report grep matches. Understand what each finding means in context.
- **Trace data flows.** A configurable URL is only dangerous if user data flows through it. Follow the code path.
- **Quote specific code** with file:line references so the reader can verify your findings.
- **Explain attacks as step-by-step scenarios.** "The operator could..." not just "this is configurable."
- **Note what's done well.** Good security practices deserve recognition.
- **Be honest about unknowns.** If you couldn't verify something (no deployment URL, endpoint was down), say so.

---

## Background: how dstack TEE works

[dstack](https://github.com/Dstack-TEE/dstack) runs Docker containers inside Intel TDX hardware enclaves. The hardware prevents the cloud provider and host OS from reading the container's memory or tampering with its execution.

**What the hardware protects against**: the cloud provider reading your data, the host OS tampering with the code, physical access attacks on the server.

**What the hardware does NOT protect against**: the person who deployed the app (the "operator"). They choose which code to run, which settings to inject, and which Docker images to use. If the code has backdoors or configurable exfiltration paths, the tamper-proof hardware will faithfully execute the exfiltration. The hardware doesn't know the difference between legitimate and malicious code -- it just runs whatever it's given and proves that it ran it.

Key concepts:
- **compose hash**: a fingerprint of the app's configuration (docker-compose + settings). The hardware attests this hash. If the compose changes, the hash changes.
- **allowed_envs**: environment variables the operator can change WITHOUT changing the compose hash. **This is the primary attack surface.** If a URL handling user data is in `allowed_envs`, the operator can redirect your data without invalidating the attestation.
- **attestation sources**: attestation data is cryptographically self-verifying, so it doesn't matter where you get it. Common sources: the app's own `/attestation` endpoint, the Phala 8090 metadata page (`{app_id}-8090.{cluster}.phala.network/`), the Trust Center (`trust.phala.com/app/{app_id}`), or a JSON file the user provides. All are equally valid -- you verify the proof, not the messenger.
- **KMS** (Key Management Service): where encryption keys come from. If the operator manages keys, they can decrypt your data. If the TEE derives keys internally (via hardware), the operator can't.
- **AppAuth**: an on-chain smart contract that records which code versions are allowed to run. If changes require a timelock (waiting period), users can see updates coming and react before they take effect.
