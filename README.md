# is-this-real-tea

Security audit tool for [dstack](https://github.com/Dstack-TEE/dstack) TEE applications. Give it a GitHub repo and a Phala Cloud URL, get back a detailed analysis of attestation, TLS binding, DevProofness, and code security.

## Two layers

### 1. `/audit` — Claude Code skill (the main thing)

```
/audit https://github.com/sangaline/tee-totalled https://4e0b5429671d8f90198c806f93e3c0a483f64cff-3000.dstack-pha-prod7.phala.network/
```

Claude clones the repo, reads the actual source code, fetches live attestation data, and produces a structured audit report covering:

- **Configuration Control** — traces every external URL to determine if user data can be exfiltrated by a malicious operator
- **Attestation & TLS** — checks TDX quote presence, signing key binding, certificate fingerprint matching
- **Build Reproducibility** — pinned images, SOURCE_DATE_EPOCH, lockfiles, CI pipeline
- **Data Flow & Storage** — maps how user data moves through the system, what gets persisted, encryption at rest
- **On-chain / KMS** — AppAuth contracts, upgrade timelocks, compose hash transparency
- **Stage Assessment** — ERC-733 classification with full checklist

Each finding includes the actual vulnerable code with file:line references, a step-by-step attack vector, and specific fix recommendations.

### 2. `dstack_audit` — Python CLI (automated scanner)

```bash
python -m dstack_audit <repo_url> <website_url> -v
```

Quick automated scan that greps 30+ patterns across 7 categories. Useful as a starting point, but the `/audit` skill produces much richer analysis by actually reading and understanding the code.

## Setup

Copy this repo's `.claude/commands/audit.md` into your project's `.claude/commands/` to get the `/audit` command.

Or clone this repo and run the Python tool directly:

```bash
git clone https://github.com/sxysun/is-this-real-tea
cd is-this-real-tea
python -m dstack_audit <repo_url> <website_url> -v
```

## What the audit covers

### Configuration Control (most critical)

The core question: **can the operator exfiltrate user data?**

TEE protects against cloud providers, but operators control `allowed_envs` — environment variables injected at runtime without changing the compose hash. If a URL handling user data is configurable via env, the operator can redirect it to their own server.

```yaml
# VULNERABLE: operator sets LLM_BASE_URL to capture all prompts
environment:
  - LLM_BASE_URL=${LLM_BASE_URL}

# SAFE: hardcoded, operator can't change it
environment:
  - LLM_BASE_URL=https://api.redpill.ai/v1
```

### Attestation & TLS

- Is there a TDX hardware quote? (empty = --dev-os, no TEE guarantees)
- Is the signing key cryptographically bound to the quote's report_data?
- Does the TLS certificate fingerprint match the attested fingerprint?
- Gateway-terminated vs TLS passthrough (end-to-end)

### ERC-733 Stage Assessment

| Stage | Name | Meaning |
|-------|------|---------|
| 0 | Ruggable | Developer can push updates or exfiltrate data without notice |
| 1 | DevProof | Upgrade transparency, no exfiltration vectors, reproducible builds |
| 2 | Decentralized | No single party controls upgrades |
| 3 | Trustless | Cryptographic multi-vendor verification |

## Dependencies

**Core:** Python 3.10+ stdlib only (no pip dependencies)

**Optional:** `dcap-qvl-cli` for TDX quote hardware verification

**Tests:** `pytest`

## Tests

```bash
pytest tests/ -v              # 52 cached tests, no network
pytest tests/ -v --run-live   # live tests against Phala Cloud
```

## References

- `references/STAGE-1-CHECKLIST.md` — full ERC-733 Stage 1 requirements with verification commands
- `references/checklist.md` — comprehensive audit checklist (7 sections, 50+ items)
- `references/report-template.md` — structured report template
- `references/erc733-summary.md` — ERC-733 overview

## Case studies

Tested against apps from [devproof-audits-guide](https://github.com/amiller/devproof-audits-guide):

| App | Stage | Key Finding |
|-----|-------|-------------|
| hermes | 0 | Pha KMS, mutable image tags |
| tee-totalled | 0 | `LLM_BASE_URL` configurable (exfiltration) |
| tokscope-xordi | 0 | `${VAR}` image refs, configurable URLs, best repro builds |
| xordi-toy-example | 1 | Reference implementation with Base KMS |
| firecrawl | 0 | No TDX quote (--dev-os), massive URL surface |
