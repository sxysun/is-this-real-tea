# TEE Security Audit -- Agent Instructions

You are checking whether a TEE (Trusted Execution Environment) app is actually safe to use, or just security theater.

The app runs inside tamper-proof hardware that the cloud provider can't read. But **the operator who deployed it might still be able to steal user data** -- unless the code is specifically set up to prevent this. Your job is to find out which case it is.

**You need**: a GitHub repo URL (required), and optionally a deployment URL or attestation data.

**Reference files** (consult during audit):
- `references/devproof-stages.md` — stage criteria (Unproven / Stage 0 / Stage 1)
- `references/live-checks.md` — endpoint heuristics, TLS binding classification
- `references/case-studies.md` — patterns from real audits
- `references/search-patterns.md` — grep patterns for common vulnerabilities
- `references/STAGE-1-CHECKLIST.md` — ERC-733 Stage 1 requirements
- `references/report-template.md` — report structure
- `references/checklist.md` — comprehensive audit checklist

**Tools** (use during audit):
- `tools/verify-compose-hash.py` — fetches 8090 metadata and verifies compose hash
- `tools/audit-checks.sh` — quick automated vulnerability scan

---

## Quick version

If you're short on time, check these four things:

1. **Read `docker-compose.yml` and find every `${VAR}` pattern.** For each one, trace whether user data flows through that variable. If it does, the operator can redirect that data to their own server. **This is the #1 vulnerability in TEE apps.**

2. **Search for attestation code** -- grep for `attestation`, `tdx`, `quote`, `dstack-sdk`, `getKey`, `rtmr`. If there's nothing, the TEE is decoration. The hardware can prove what code is running, but if the app never asks it to, the proof doesn't exist. If there is code, check whether verification is actually enforced or just logged and ignored. Also check if attestation data is available from ANY source (the app, 8090, Trust Center) -- the cryptographic proof is self-verifying regardless of where it comes from.

3. **Check Dockerfiles for `FROM image@sha256:`** -- if base images aren't pinned by exact hash, anyone could swap in different code and the builds can't be verified.

4. **If you have a deployment URL, verify the TLS certificate is bound to the TEE** -- connect to the site, get the cert fingerprint, compare it against what the app's `/attestation` endpoint claims. If they don't match (or there's no attestation endpoint), you can't prove your connection actually reaches the TEE.

If any of these fail, **the operator can still steal user data**. Report what you find.

---

## How to think about trust

Before checking anything, understand what you're actually verifying — and what you're not.

### What the compose hash actually covers

The compose hash is a SHA-256 of the `docker-compose.yml` file text and its deploy-time settings. That's it. It does **not** cover:
- The contents of Docker images referenced in the compose file
- The dependencies installed inside those images
- Runtime behavior triggered by environment variables
- Data that leaves the TEE after processing
- DNS resolution of hostnames in the compose file
- Sidecar processes, init containers, or pre-launch scripts (these are part of `app_compose` but easy to overlook)

When you see "compose hash matches," that means the *configuration file* is what was attested. It says nothing about whether the *code that configuration points to* is safe.

### The chain of trust has many links

Trace the full chain. Each link can break independently:

```
compose_hash
  → docker_compose_file (text of the config)
    → image reference (tag or digest)
      → image contents (layers, binaries, scripts)
        → dependencies (pip packages, npm modules, system libraries)
          → runtime behavior (what the code actually does when executed)
            → data destinations (where user data ends up)
```

Most audits only check the first link (compose hash matches). A thorough audit traces every link. Ask at each step: "Who controls this? Can the operator influence it without changing the compose hash?"

### Every channel the operator can influence

Environment variables (`allowed_envs`) are the obvious one. But operators can also influence:
- **Image selection**: `${IMAGE}` in docker-compose means the operator picks what code runs
- **Pre-launch scripts**: code that runs before the container starts, outside the image
- **Runtime config files**: `.env`, YAML, TOML files mounted or generated at startup
- **Database connection strings**: if the operator controls where the database lives, they control the data
- **DNS resolution**: the operator can point hostnames to their own servers
- **Package registries**: custom pip/npm registries configured via env var (`--extra-index-url`, `NPM_CONFIG_REGISTRY`)
- **Mounted volumes**: data shared between containers or from the host
- **Sidecar containers**: other containers in the compose that share the network namespace

### Every channel data can leave the TEE

HTTP requests to external services are the obvious exfiltration path. But data can also leave through:
- **DNS queries**: data encoded in DNS lookups (`sensitive-data.attacker.com` leaks data to whoever controls the DNS resolver or the target domain)
- **Database writes**: data stored "inside the TEE" but the database replicates to an external server, or the database connection string points outside the TEE
- **Logging/analytics services**: PostHog, Sentry, Datadog, custom logging — if the endpoint is configurable, user data in error messages or analytics events is exfiltrable
- **Error responses**: sensitive data leaked through HTTP headers, error messages, or stack traces sent to external error tracking
- **Timing side channels**: information leaked through response timing differences (less likely in practice but worth noting for high-security apps)
- **Response metadata**: HTTP headers, status codes, or response sizes that encode information about user data

### "Attested" does not mean "safe"

Attestation proves the configuration hash. It proves the hardware is real. It proves the code hasn't been tampered with *at the boot level*. It does **not** prove:
- The code is honest (the hardware will faithfully execute exfiltration if the code tells it to)
- The dependencies are safe (a malicious npm package inside a correctly-attested image still runs)
- The operator can't influence behavior (env vars, DNS, image selection are outside the hash)
- The data stays protected after processing (the TEE protects memory, not network traffic)

### The supply chain question

Who built the image? If the operator controls the CI pipeline:
- A "correct" image digest just means the operator's build is consistent, not that the code is safe
- Trace the full path: source code → build system → container registry → deployment
- If the repo is public but the build pipeline is private, you can't verify the image matches the source
- Even with reproducible builds, verify that the *source* is what was audited, not just that the build is deterministic

**Use this mental model throughout the audit.** When you find something — an env var, a URL, a dependency — ask: "Where does this sit in the chain of trust? Who controls it? What could go wrong?" If you can reason from these principles, you'll catch vulnerabilities that aren't on any checklist.

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

### Phase 1c: Verify attestation cryptographically

**Compose hash mismatch = stop and report.** If `verify-compose-hash.py` shows the computed hash doesn't match the expected hash, the metadata page is lying or corrupted. Nothing else can be trusted. Report this immediately.

If attestation data is available, verify it cryptographically rather than just checking it exists.

**Step 1: Verify the TDX quote (requires dcap-qvl)**
```bash
# Install dcap-qvl if not present
CFLAGS="-g0" cargo install dcap-qvl-cli

# Write quote hex to file and verify
echo "<quote_hex>" > /tmp/quote.hex
dcap-qvl verify --hex /tmp/quote.hex
```
This verifies the Intel TDX quote signature against DCAP collateral and extracts RTMRs, mr_config_id, and report_data. Check:
- **TCB status**: "UpToDate" is ideal, "SWHardeningNeeded" is acceptable, anything else is a concern
- **mr_config_id**: contains the compose hash (format: `01` + 32-byte SHA-256 hash + zero padding)

**Step 2: Compare compose hash**
Compute `SHA-256(canonical_json(app_compose))` where canonical JSON uses `separators=(',', ':')` and `sort_keys=True`. Compare this against the hash extracted from `mr_config_id[2:66]`. If they match, the deployed configuration is what the hardware attested.

**Step 3: Verify report_data binding**
The report_data field (64 bytes) typically contains:
- Bytes 0-31: signing address (or app-specific binding)
- Bytes 32-63: nonce

**Step 4: Event log replay (optional, requires dstack-verifier)**
```bash
# Run the verifier service
docker run -d -p 8080:8080 dstacktee/dstack-verifier

# POST quote + event_log + vm_config for full verification
curl -X POST http://localhost:8080/verify \
  -H "Content-Type: application/json" \
  -d '{"quote": "<hex>", "event_log": "<base64>", "vm_config": "<json>"}'
```
This replays the TCG event log against RTMRs using QEMU, verifying boot integrity.

**If dcap-qvl is NOT installed**: Parse the quote manually to extract measurements (fields are at fixed offsets in the TDX Quote v4 structure), but note that the quote signature has NOT been verified.

**If you cannot verify the TDX quote, EXPLICITLY STATE THIS.** Write:
> TDX quote verification: NOT PERFORMED — [reason]. The compose hash matches but the attestation chain is unverified.

Do not silently pass this check. "NOT VERIFIED" is an honest finding.

### Phase 1 output

Record these facts before proceeding:

```
REPO: <path or url>
COMPOSE_FILES: <list>
DOCKERFILES: <list>
APP_ID: <if known>
COMPOSE_HASH: <from verify-compose-hash.py or 8090>
COMPOSE_HASH_MATCH: <yes/no/not checked>
ALLOWED_ENVS: <list from app_compose>
TLS_SUBJECT: <CN>
TLS_FINGERPRINT: <sha256>
ATTESTATION_ENDPOINTS: <list of working endpoints>
```

### Quick automated scan

Before deep analysis, run the automated checker to identify areas of concern:
```bash
./tools/audit-checks.sh /path/to/repo
```

If you have an app_id, verify the compose hash:
```bash
python3 tools/verify-compose-hash.py <app-id> [cluster]
```

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

**Environment variable risk taxonomy** — classify each variable in `allowed_envs`:

| Category | Risk | Example |
|----------|------|---------|
| **Data destination** | CRITICAL | URL that receives user content (API_URL, LLM_BASE_URL, POSTHOG_HOST) |
| **Code/image selector** | CRITICAL | Chooses what code runs (IMAGE_TAG, MODULE_URL) |
| **API key / credential** | HIGH | Authentication token (API_KEY, BOT_TOKEN) — operator holds the key |
| **Feature flag** | MEDIUM | Toggles behavior (ENABLE_LOGGING, DEBUG) |
| **Cosmetic** | LOW | Display name, theme (APP_NAME, BRAND_COLOR) |

For CRITICAL variables, read the code that uses them and trace the full data flow:
1. Where does user data enter? (HTTP handler, WebSocket, etc.)
2. Where does it go? (Follow the variable through the code)
3. Does it reach a URL controlled by this env var?
4. Provide exact file:line evidence.

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

#### 2a-extra. Beyond env vars: other operator influence channels

Env vars are the most common attack surface, but not the only one. Also check:

**Dynamic code loading**: Search for patterns that let the operator cause the app to execute code from a source they control:
- JavaScript/TypeScript: `import()`, `require()` with variable paths, `eval()`, `new Function()`, `vm.runInContext()`
- Python: `importlib.import_module()`, `exec()`, `eval()`, `subprocess`, `os.system()`, `__import__()`
- General: `dlopen`, WASM loading, plugin systems, webhook handlers that execute payloads

If any of these load code from a path or URL controlled by an env var, the operator can inject arbitrary code.

**Configuration files outside the compose hash**: Look for `.env` files, YAML/TOML/JSON config files that are read at runtime. If these are generated by a pre-launch script or mounted from outside the image, the operator controls them even though the compose hash is valid.

**Database as exfiltration vector**: If the database connection string is in `allowed_envs`, the operator controls where data is stored. Check:
- `DATABASE_URL`, `POSTGRES_*`, `MONGO_*`, `REDIS_URL` in allowed_envs
- Whether the database supports replication to external servers
- Whether connection strings use hostnames (resolvable by operator-controlled DNS) vs hardcoded IPs

**Dependency confusion / supply chain**: Check whether package installation happens at runtime (not just build time):
- `pip install` or `npm install` in entrypoint scripts or pre-launch scripts
- Custom registries configured via env var (`PIP_EXTRA_INDEX_URL`, `NPM_CONFIG_REGISTRY`)
- Unpinned dependencies pulled at container startup

#### 2a-ii. Check docker_compose_file for ${VAR} patterns

If you have the deployed `docker_compose_file` (from app_compose via 8090 metadata), search it:

For each `${VAR}`:
- Is this variable in `allowed_envs`? If yes, the operator controls it.
- Does it point to an image? → operator controls what code runs
- Does it point to a URL? → operator can redirect traffic
- Is it a hardcoded value like `API_URL=https://...`? → good, baked into compose hash

#### 2a-iii. Check for pre_launch_script

If `pre_launch_script` exists in app_compose, read it carefully. This runs before docker-compose up and can do anything: download binaries, modify config files, set additional environment variables.

#### 2a-iv. Look for outbound data paths

Use patterns from `references/search-patterns.md`:

- Find all HTTP clients in the code (httpx, requests, aiohttp, fetch, axios)
- Find where user content is sent (user_prompt, message, content, payload, body)
- For each outbound call: is the destination hardcoded or configurable?

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

**Non-obvious exfiltration channels** — also check these:

- **DNS exfiltration**: If the app resolves hostnames dynamically (especially based on user input or configurable domains), data can be encoded in DNS queries. The DNS resolver sees every lookup. Search for DNS resolution calls with variable hostnames.
- **Logging and analytics**: Search for PostHog, Sentry, Datadog, LogRocket, Mixpanel, or custom logging. If the analytics endpoint is configurable via env var, user data in logged events (error messages, request bodies, user actions) is exfiltrable. Even hardcoded analytics endpoints leak data to third parties — note this.
- **Error reporting**: Stack traces and error messages often contain user data (input that caused the error, request context). If these go to an external error tracking service, that's a data leak. Check `Sentry.init()`, error middleware, unhandled exception handlers.
- **Response metadata leakage**: HTTP headers, detailed error messages, or timing differences can leak information about user data to network observers outside the TEE. Less critical than direct exfiltration but worth noting.
- **Database replication**: Data stored in a database "inside the TEE" may not stay there. Check if the database configuration allows replication, if the connection string is operator-controlled, or if the database service runs outside the TEE (common with managed databases like RDS).

#### 2e. Can the operator push silent updates?

- Find contract addresses in the code (look for AppAuth, on-chain compose hash registry)
- Check if there's a timelock (waiting period before code changes take effect)
- Note which blockchain (Base, Ethereum, etc.)
- If there's no public upgrade log, the operator can swap the code at any time without anyone knowing

### Phase 2 decision gate

Before proceeding, produce a clear statement:

> **Can the operator redirect user data?** YES / NO / PARTIALLY
>
> Evidence: [list the exact env vars and code paths]
>
> Example: The operator controls `LLM_BASE_URL` (in allowed_envs) which is loaded at
> `src/config.py:28` and receives all user prompts via the chat endpoint at `src/api.py:45`.
> This means the operator can point it to their own server and capture all conversations.

This verdict is more useful than any numerical score.

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

#### 4a. Commit-to-deployment tracing

Can you trace from compose_hash → docker_compose_file → image reference → git commit?

- Extract image references from docker_compose_file in app_compose
- If images use tags containing commit SHAs (e.g., `v1.1.0-58ad3f2`), note the commit
- If images are `${VAR}` references: **flag as unverifiable** (the operator controls what runs)
- If images are pinned by `@sha256:` digest: good, but verify the digest matches

**IMPORTANT:** If the image is behind a `${VAR}` in allowed_envs, you CANNOT verify what is actually running. This is a critical audit blind spot.

#### 4b. Configuration comparison

- Compare the deployed docker-compose from attestation data against compose files in the repo
- Check if deployed images match what the repo would build
- Map `allowed_envs` against actual environment variable usage in code
- Flag any `${VAR}` image references (operator can swap the entire container without changing the code hash)

#### 4c. Upgrade transparency

**Which KMS does the app use?**

- **Pha KMS** (default): No public upgrade log. Trust Center shows current state only. You cannot query what was running last week. Flag this.
- **Base KMS** (`kms-base-prod7` or similar): On-chain transparency. Query events:

```bash
# Query AppAuth contract for compose hash history
cast call <APP_CONTRACT> "getComposeHashes()" --rpc-url https://mainnet.base.org

# Query ComposeHashAdded events
cast logs --from-block 0 --address <APP_CONTRACT> \
  "ComposeHashAdded(bytes32)" --rpc-url https://mainnet.base.org

# Check for timelock
cast call <APP_CONTRACT> "getTimelock()" --rpc-url https://mainnet.base.org
```

If Base KMS: check how many compose hashes have been authorized historically. Multiple authorized hashes may allow downgrade attacks.

**Is there a DEPLOYMENTS.md or equivalent?** Check the repo for human-readable upgrade history.

**Is there a timelock?** Without a timelock, the operator can push a malicious upgrade and immediately start capturing data.

#### 4d. DECISION: Upgrade transparency verdict

> **Can the operator silently upgrade?** YES / NO / PARTIALLY
>
> KMS: [Pha / Base / unknown]
> Timelock: [yes (N days) / no / unknown]
> Upgrade history: [on-chain / DEPLOYMENTS.md / none]

### Phase 5: Stage assessment & report

#### 5a. Apply stage criteria

Reference `references/devproof-stages.md` and `references/STAGE-1-CHECKLIST.md`.

**Stage 1 requires ALL of these** (fail any = Stage 0):

1. On-chain attestation with public upgrade log (Base KMS or equivalent)
2. Auditable code (public source or formal verification)
3. Reproducible code measurement (pinned images, SOURCE_DATE_EPOCH, lockfiles)
4. Developer has no access to secrets (no fallback keys, no DEV_MODE bypass)
5. Upgrade process with notice period (timelock)
6. No centralized infrastructure dependency (except TEE vendor)
7. No backdoors or debug paths

If ANY of these fail, the app is Stage 0. Be precise about WHICH requirement(s) fail.

If the evidence is too thin to even confirm TEE usage, classify as **Unproven**.

#### 5b. Generate report

Structure your report like this:

```markdown
## One-Glance Card

**Verdict:** [SAFE / PARTIAL / NOT SAFE] — [one-line reason]

| Dimension | Status | Signal | Evidence |
|-----------|--------|--------|----------|
| Operator gap | PASS/FAIL/PARTIAL | GREEN/YELLOW/RED | [key finding] |
| Attestation integrity | PASS/FAIL/PARTIAL | GREEN/YELLOW/RED | [compose hash, TDX verification] |
| TLS binding | PASS/FAIL/PARTIAL | GREEN/YELLOW/RED | [cert fingerprint vs attestation] |
| Build reproducibility | PASS/FAIL/PARTIAL | GREEN/YELLOW/RED | [pinned images, SOURCE_DATE_EPOCH] |
| Upgrade transparency | PASS/FAIL/PARTIAL | GREEN/YELLOW/RED | [KMS type, timelock, history] |

Signal key: GREEN=closed, YELLOW=partial/unknown, RED=attackable

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
| TDX quote cryptographically verified (dcap-qvl) | | |
| Compose hash matches mr_config_id in quote | | |
| Report data binding verified | | |
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
[List things you couldn't check and why. ALWAYS include these categories:]
- **Dependency supply chain**: "Dependencies inside the image were not individually audited. A compromised transitive dependency would not be caught by this review."
- **Runtime-conditional behavior**: "Code paths triggered only by specific operator-controlled inputs may exist but not be visible in static analysis."
- **Build pipeline integrity**: "Whether the deployed image was built from the audited source code [was / was not] verified. [Detail]."
- [Plus any audit-specific gaps. Examples:]
- "Could not verify TLS binding because the attestation endpoint was unreachable"
- "Could not check if the deployed image matches the source because no deployment URL was provided"

## Recommendations

### The app is unsafe without these
[Specific fixes with file paths -- the attacks listed above]

### Important improvements
[Things that significantly reduce risk]

### To fully tie the operator's hands
[What would need to change so the operator provably cannot interfere]

## Verification Status

Always end with a clear accounting of what was and wasn't verified:

| Check | Status | Notes |
|-------|--------|-------|
| Compose hash | Verified / Not checked | [detail] |
| TDX quote | Verified / NOT VERIFIED | [tool used or why not] |
| TLS binding | Strong / Partial / None | [detail] |
| Image-to-source | Traced / Unverifiable | [detail] |
| Reproducible build | Verified / Not attempted | [detail] |
| On-chain history | Queried / Not available | [detail] |

## Audit Scope & Limitations

> This is a code-level trust model audit, not a penetration test. It checks whether the operator can structurally redirect or access user data. It does NOT audit transitive dependencies, test for memory corruption, or guarantee the absence of all possible vulnerabilities. A "SAFE" verdict means no operator gap was found in the audited code — not that exploitation is provably impossible.

## Recommended Next Step

End with the single highest-leverage change the project should make to move closer to Stage 1. Be specific.
```

---

## What this does NOT do

- **No numerical scoring.** A reasoned verdict with evidence is more useful than "42/100".
- **No automated pass/fail.** You reason about each dimension. A variable named `CALLBACK_ADDR` that exfiltrates data is caught by reading the code, not by regex-matching variable names containing "URL".
- **No silent assumptions.** If you can't verify something, say so explicitly. "TDX quote: NOT VERIFIED" is an honest finding. Silently passing is not.

## Limits of this audit

Be explicit in every report about what this audit *cannot* catch. The report consumer needs to understand the boundaries.

- **This is a code-level trust model audit, not a penetration test.** It identifies structural gaps in how the operator can influence the app. It does not attempt to exploit those gaps, test for memory corruption, or probe running services.
- **Supply chain attacks in dependencies are not fully auditable by reading application code.** A malicious transitive dependency (e.g., a compromised npm package three levels deep) would not be caught. Dependency auditing requires specialized tools and is out of scope.
- **Runtime behavior triggered by operator-controlled inputs may not be visible in static analysis.** If the operator sets `DEBUG=true` and that triggers a code path that exfiltrates data, this audit will try to find it — but complex conditional logic or obfuscated paths may be missed.
- **The build pipeline is trusted if the image digest matches.** If the operator controls the CI/CD system, a matching digest means the build is consistent, not that the source is safe. This audit checks the *source code*, not the build infrastructure.
- **A "SAFE" verdict means "no operator gap found in the audited code."** It does NOT mean "provably impossible to exploit." No single-pass code review can provide that guarantee. Explicitly state this in every report.
- **Interactions between components may create vulnerabilities invisible to single-service analysis.** If the app has multiple containers, the interactions between them (shared networks, volumes, service discovery) are checked at the compose level but may have subtleties that require integration testing to catch.

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
