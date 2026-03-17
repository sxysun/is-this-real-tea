Check a TEE deployment's safety by analyzing a repo and live URL under the DevProof model.

Arguments: $ARGUMENTS

Parse the arguments from $ARGUMENTS. The user may provide any combination of:
- **repo** — local path or GitHub URL (at least one of repo or url required)
- **url** — live website URL to verify
- **attestation_url** — optional 8090 metadata endpoint or attestation URL

If you have only a live URL, work backwards from it. If you have only a repo, note that live verification is limited.

## Instructions

Follow the full audit methodology in `AGENT.md`. Work through all 5 phases:

1. **Gather attestation data** — fetch 8090 metadata, get TLS cert, probe attestation endpoints. Use `tools/verify-compose-hash.py` for compose hash verification.
2. **Analyze the source code** — trace every configurable URL and env var through the code. Classify each variable by risk (see the env var taxonomy in AGENT.md Phase 2a). Read the code, don't just grep.
3. **Build reproducibility verification** — check image pinning, SOURCE_DATE_EPOCH, attempt rebuild if possible.
4. **Cross-reference** — compare deployed config against repo, map allowed_envs to code usage.
5. **Generate report** — produce the one-glance card and full report per the template in `references/report-template.md`. Apply stage criteria from `references/devproof-stages.md`.

## Quick automated scan first

Before deep analysis, run the automated checker to identify areas of concern:
```bash
./tools/audit-checks.sh /path/to/repo
```

## Decision gates

At each phase boundary, produce a clear verdict before proceeding:
- Phase 1 output: list of raw facts (app_id, compose_hash, TLS fingerprint, endpoints found)
- Phase 2 decision: "Can the operator redirect user data? YES/NO/PARTIALLY" with evidence
- Phase 3 decision: "Can the build be reproduced? YES/NO/PARTIALLY"
- Phase 4 decision: "Does the deployed config match the repo? YES/NO/PARTIALLY"
- Phase 5: one-glance card + full report

## Reference files

Consult these during the audit:
- `references/devproof-stages.md` — stage criteria (Unproven / Stage 0 / Stage 1)
- `references/live-checks.md` — endpoint heuristics, TLS binding classification
- `references/case-studies.md` — patterns from real audits
- `references/search-patterns.md` — grep patterns for common vulnerabilities
- `references/STAGE-1-CHECKLIST.md` — ERC-733 Stage 1 requirements
- `references/report-template.md` — report structure

## What this does NOT do

- No numerical scoring. A reasoned verdict with evidence is more useful than "42/100".
- No automated pass/fail. You reason about each dimension.
- No silent assumptions. If you can't verify something, say so explicitly.
