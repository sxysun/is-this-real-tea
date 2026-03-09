# is-this-real-tea

Automated security audit tool for [dstack](https://github.com/Dstack-TEE/dstack) TEE applications. Give it a GitHub repo and a Phala Cloud URL, get back whether the app is safe to interact with.

```bash
python -m dstack_audit https://github.com/sangaline/tee-totalled \
  https://4e0b5429671d8f90198c806f93e3c0a483f64cff-3000.dstack-pha-prod7.phala.network/
```

## What it does

A 6-phase pipeline that checks whether a dstack TEE app is **DevProof** (ERC-733 Stage 1) or **Ruggable** (Stage 0):

| Phase | What it checks |
|-------|---------------|
| 1. URL Parse | Extracts app_id, cluster, port from Phala Cloud URL |
| 2. Attestation | Fetches 8090 endpoint, extracts app_compose, checks for TDX quote |
| 3. TLS Binding | Verifies certificate fingerprint matches TEE attestation |
| 4. Code Analysis | Clones repo, greps 30+ patterns across 7 vulnerability categories |
| 5. Cross-Reference | Compares deployed compose vs source, flags exfiltration vectors |
| 6. Stage Assessment | Applies ERC-733 checklist to determine Stage 0 or 1 |

### Stage 0 (Ruggable) — any one of:
- No TDX quote (--dev-os)
- Pha KMS without on-chain AppAuth
- Mutable image tags (no `@sha256:` pinning)
- Configurable URLs that can exfiltrate user data
- No upgrade timelock

### Stage 1 (DevProof) — requires all of:
- On-chain KMS with AppAuth contract
- Pinned image digests
- Timelock on upgrades
- No configurable exfiltration vectors
- TLS binding verified
- Reproducible builds

## Usage

### CLI

```bash
# Basic audit
python -m dstack_audit <repo_url> <website_url>

# Verbose (progress to stderr)
python -m dstack_audit <repo_url> <website_url> -v

# Save report to file
python -m dstack_audit <repo_url> <website_url> -o report.md
```

### Claude Code slash command

Copy `audit.md` to `.claude/commands/audit.md` in your project, then:

```
/audit https://github.com/org/repo https://appid-3000.cluster.phala.network/
```

Claude will run the audit, interpret the report, explain attack vectors, and give a verdict.

## Dependencies

**Core:** Python 3.10+ stdlib only (`urllib`, `json`, `hashlib`, `re`, `subprocess`, `ssl`, `socket`)

**Optional:** `dcap-qvl-cli` for TDX quote hardware verification

**Tests:** `pytest`

## Tests

```bash
# Run all cached tests (no network required)
pytest tests/ -v

# Run live tests against real Phala Cloud endpoints
pytest tests/ -v --run-live
```

## Code analysis categories

The grep-based scanner checks 7 categories (patterns in `dstack_audit/patterns/search_patterns.json`):

1. **Configurable URLs** — `${..._URL}`, `LLM_BASE_URL`, `API_URL` in compose/env
2. **External network calls** — outbound HTTP, WebSocket, DNS
3. **Attestation code** — quote verification, TappdClient usage
4. **Red flags** — HACK comments, verification bypasses, dev fallbacks, eval/exec
5. **Build reproducibility** — pinned digests, SOURCE_DATE_EPOCH, lockfiles
6. **Secrets/storage** — KMS usage, secret env vars, encryption code
7. **Smart contracts** — AppAuth interaction, contract addresses, on-chain libraries

## Case studies

Tested against apps from [devproof-audits-guide](https://github.com/amiller/devproof-audits-guide):

| App | Expected Stage | Key Finding |
|-----|---------------|-------------|
| hermes | 0 | Pha KMS, mutable image tags |
| tee-totalled | 0 | `LLM_BASE_URL` configurable (exfiltration) |
| tokscope-xordi | 0 | `${VAR}` image refs, configurable URLs |
| xordi-toy-example | 0/1 | Reference implementation |
| firecrawl | 0 | No TDX quote (--dev-os) |
