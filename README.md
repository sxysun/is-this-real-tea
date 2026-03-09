# is-this-real-tea

Verify whether a [dstack](https://github.com/Dstack-TEE/dstack) TEE application is safe to interact with. Give it a GitHub repo (and optionally a deployment URL), get back a structured security audit.

---

## For users

Tell your AI agent:

> Read https://raw.githubusercontent.com/sxysun/is-this-real-tea/main/AGENT.md and then audit this TEE app: `<github_repo_url>` deployed at `<website_url>`

That's it. The agent will know what to do.

---

## What gets checked

| Area | Core Question |
|------|--------------|
| **Configuration Control** | Can the operator redirect user data to their own server? |
| **Attestation & TLS** | Is there a TDX hardware quote? Is the signing key bound to it? |
| **Build Reproducibility** | Can you rebuild the exact same image from source? |
| **Data Flow** | Where does user data go? What leaves the TEE boundary? |
| **On-chain / KMS** | Are upgrades transparent? Is there a timelock? |

The output is an [ERC-733](https://draftv4.erc733.org) stage assessment:

| Stage | Name | What it means |
|-------|------|---------------|
| 0 | Ruggable | Operator can exfiltrate data or push silent updates |
| 1 | DevProof | Upgrade transparency, no exfiltration vectors, reproducible builds |
| 2 | Decentralized | No single party controls upgrades |
| 3 | Trustless | Cryptographic multi-vendor verification |

**Most apps today are Stage 0.** Stage 1 is achievable with attention to detail.

## Why this matters

TEE protects your data from the cloud provider, but **not from the operator**. The operator controls `allowed_envs` -- environment variables injected at deploy time without changing the attested compose hash. If a URL handling your data is configurable via env, the operator can silently redirect your data to their own server:

```yaml
# DANGEROUS: operator sets LLM_BASE_URL to their proxy, captures all your prompts
environment:
  - LLM_BASE_URL=${LLM_BASE_URL}

# SAFE: hardcoded in the attested compose, operator can't change it
environment:
  - LLM_BASE_URL=https://api.openai.com/v1
```

This tool traces every external URL in the codebase to determine if user data can be exfiltrated through operator-controlled configuration.

## Case studies

| App | Stage | Key Finding |
|-----|-------|-------------|
| tee-totalled | 0 | `LLM_BASE_URL` operator-configurable -- all user prompts exfiltrable. Signature verification is log-only. |
| tokscope-xordi | 0 | RCE via `loadModuleFromUrl` (bare `require()` on fetched code). `allowed_envs` covers 2 of ~15 critical vars. |
| xordi-toy-example | 0 | Hardcoded fallback encryption key in public source. Same RCE as tokscope. |
| hermes | 0 | Zero attestation code despite dstack-sdk import. 7+ unauthenticated admin endpoints. All data to Firebase in plaintext. |
| firecrawl | 0 | No TDX quote (--dev-os), massive configurable URL surface |

## For developers

### Install the Claude Code skill

Copy the audit skill into your project:

```bash
mkdir -p .claude/commands
curl -o .claude/commands/audit.md https://raw.githubusercontent.com/sxysun/is-this-real-tea/main/.claude/commands/audit.md
```

Then use it:

```
/audit https://github.com/user/repo https://app-3000.dstack-pha-prod7.phala.network/
```

### Python CLI (quick scan)

```bash
git clone https://github.com/sxysun/is-this-real-tea
cd is-this-real-tea
python -m dstack_audit <repo_url> <website_url> -v
```

Automated grep of 30+ patterns across 7 categories. Useful as a starting point, but the agent-based audit produces much richer analysis.

### Tests

```bash
pytest tests/ -v              # 52 cached tests, no network
pytest tests/ -v --run-live   # live tests against Phala Cloud
```

## References

- [ERC-733 Draft v4](https://draftv4.erc733.org) -- the security stages framework
- [dstack](https://github.com/Dstack-TEE/dstack) -- the TEE runtime
- [devproof-audits-guide](https://github.com/amiller/devproof-audits-guide) -- case studies and methodology
- `references/STAGE-1-CHECKLIST.md` -- full Stage 1 requirements with verification commands
- `references/erc733-summary.md` -- ERC-733 overview
