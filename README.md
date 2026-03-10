# is-this-real-tea

Check whether a TEE app is actually safe, or just security theater.

A [TEE](https://github.com/Dstack-TEE/dstack) (Trusted Execution Environment) app runs inside tamper-proof hardware. The cloud provider can't read your data. But **the person who deployed the app still can** -- unless the code is set up to prevent it. Most apps haven't done this yet.

This tool checks whether they have.

---

## For users

Tell your AI agent:

> Read https://raw.githubusercontent.com/sxysun/is-this-real-tea/main/AGENT.md and then audit this TEE app: `<github_repo_url>` deployed at `<website_url>`

That's it. The agent will know what to do.

---

## What gets checked

| Question | Why it matters |
|----------|---------------|
| **Can the operator redirect your data?** | The #1 risk. If the app sends your data to a URL the operator can change at deploy time, they can silently reroute it to their own server. |
| **Is the hardware actually attesting?** | TEE hardware can prove what code is running. If the app doesn't use this, or uses it wrong, the "secure hardware" claim means nothing. |
| **Can you rebuild the code and get the same result?** | If you can't reproduce the exact same image from source code, you can't verify that what's running matches what's published. |
| **Where does your data go?** | Data that leaves the TEE boundary (to an external database, API, etc.) is no longer protected by the hardware. |
| **Can the operator push silent updates?** | If the operator can swap the code instantly with no public record, they can change behavior without anyone noticing. |

## The trust spectrum

There's a huge gap between "runs in a TEE" and "actually safe." Here's how to think about it:

### The operator can still steal your data

The app runs inside secure hardware, but the person who deployed it can still redirect your data, push silent updates, or swap out the code. **This is where most apps are today.** The TEE protects against the cloud provider, but if you're worried about the operator -- you have no guarantees.

How to spot this:
- URLs that handle your data are configurable (the operator can change where your data goes)
- No public log of code changes
- Docker images use tags instead of exact hashes (the operator can swap what's running)
- The app has development backdoors or fallback modes

### The operator's hands are tied

The code is open source. Anyone can rebuild the exact same image and verify it matches what's deployed. Every code change is publicly logged with a waiting period before it takes effect. There are no configurable backdoors -- all URLs handling your data are baked into the attested code. The TLS certificate is cryptographically bound to the hardware attestation, so you can verify you're talking to the real TEE, not a proxy.

How to verify:
- All external URLs are hardcoded (not env-variable controlled)
- Docker images are pinned by exact hash
- Builds are reproducible (you can rebuild from source and get the same hash)
- Code changes go through a public on-chain registry with a timelock
- The TLS cert fingerprint matches what the TEE attests

### No single person controls updates

Multiple parties must agree before the code can change. No single developer, company, or operator can push an update alone. The app runs across multiple TEE providers so even if one hardware vendor is compromised, it keeps working.

*This is aspirational -- very few apps have reached this level.*

## Why this matters

TEE protects your data from the cloud provider, but **not from the operator**. The operator controls environment variables that get injected at deploy time without changing the attested code hash. If a URL handling your data is configurable via env, the operator can silently redirect your data:

```yaml
# DANGEROUS: operator can change where your prompts go
environment:
  - LLM_BASE_URL=${LLM_BASE_URL}

# SAFE: baked into the attested code, operator can't change it
environment:
  - LLM_BASE_URL=https://api.openai.com/v1
```

This tool traces every external URL in the codebase to determine if your data can be stolen through operator-controlled configuration.

## Case studies

| App | Can the operator steal data? | Key Finding |
|-----|-----|-------------|
| tee-totalled | **Yes** | The URL where your prompts are sent (`LLM_BASE_URL`) is configurable by the operator. They can redirect all your conversations to their own server. The code has signature verification but it only logs failures -- it doesn't actually block anything. |
| tokscope-xordi | **Yes** | The operator can inject arbitrary code into the TEE via a module loader that downloads and executes JavaScript from a URL they control. Only 2 of ~15 security-critical settings are covered by attestation. |
| xordi-toy-example | **Yes** | The fallback encryption key is hardcoded in the public source code (`tee-enclave-key-material-32chars`). Anyone who reads the repo can decrypt user cookies. |
| hermes | **Yes** | The app imports the TEE SDK but never actually uses it -- zero attestation code. 7+ admin endpoints have no authentication at all. All user data is stored in Firebase in plaintext, outside the TEE. |
| firecrawl | **Yes** | Not running on real TEE hardware (dev mode). The hardware attestation quote is empty. Massive number of configurable URLs that could redirect user data. |

## For developers

### Install the Claude Code skill

```bash
mkdir -p .claude/commands
curl -o .claude/commands/audit.md https://raw.githubusercontent.com/sxysun/is-this-real-tea/main/.claude/commands/audit.md
```

Then: `/audit https://github.com/user/repo https://deployed-app-url/`

### Python CLI (quick scan)

```bash
git clone https://github.com/sxysun/is-this-real-tea
cd is-this-real-tea
python -m dstack_audit <repo_url> <website_url> -v
```

### Tests

```bash
pytest tests/ -v              # 52 cached tests, no network
pytest tests/ -v --run-live   # live tests against real deployments
```

## References

- [dstack](https://github.com/Dstack-TEE/dstack) -- the TEE runtime
- [ERC-733 Draft](https://draftv4.erc733.org) -- formal security stages framework (the academic version of the above)
- [devproof-audits-guide](https://github.com/amiller/devproof-audits-guide) -- case studies and methodology
