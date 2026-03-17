# Case Studies

Use these comparisons when the auditor finds a familiar failure mode or the user wants concrete examples.

## Patterns from real audits

### tee-totalled

**Failure mode**: Operator-configurable LLM endpoint.

The URL where user prompts are sent (`LLM_BASE_URL`) is configurable by the operator. They can redirect all conversations to their own server. The code has signature verification but it only logs failures -- it doesn't actually block anything.

Useful for:
- operator-configurable URL as primary attack vector
- "verification exists but doesn't enforce" pattern

### tokscope-xordi

**Failure mode**: `image: ${VAR}` as an audit blind spot.

The operator can inject arbitrary code into the TEE via a module loader that downloads and executes JavaScript from a URL they control. Only 2 of ~15 security-critical settings are covered by attestation. Release notes claim a digest without binding it into attested config.

Useful for:
- "the repo looks okay, but the operator still controls what actually runs"
- showing the difference between publishing a hash and binding it to attestation

### xordi-toy-example

**Failure mode**: Hardcoded fallback key.

The fallback encryption key is hardcoded in the public source code (`tee-enclave-key-material-32chars`). Anyone who reads the repo can decrypt user cookies.

Useful for:
- Stage 0 classification
- compose hash exists but reproducibility is incomplete
- development secrets leaking into production

### hermes

**Failure mode**: TEE as decoration.

Hardware attestation exists (RTMRs present, Trust Center verified), but the app code never uses the TEE SDK for key derivation. Firebase credentials are in `allowed_envs` -- the operator can point the app at a different database. 7+ admin endpoints have no authentication. All user data is stored in Firebase outside the TEE.

Useful for:
- "TEE is present but unused" pattern
- data stored outside TEE boundary
- unauthenticated admin endpoints

### firecrawl

**Failure mode**: Not running on real TEE hardware.

Dev mode detected -- the hardware attestation quote is empty. Massive number of configurable URLs that could redirect user data.

Useful for:
- detecting dev mode / fake TEE
- empty TDX quote as a red flag

### near-private-chat

**Relatively strong pattern**.

Useful for:
- attestation endpoint discovery
- dstack 8090 metadata extraction
- TLS certificate binding concepts

Watch for:
- backend attestation fetching without full verification

### talos

**Relatively strong pattern**.

Useful for:
- strong repo-to-image comparison
- showing that repo-to-artifact matching is possible and valuable

Watch for:
- image match alone still does not solve upgrade transparency

### primus

**Limited auditability pattern**.

Useful for:
- image-only auditability
- explaining the difference between "on GitHub" and "actually auditable"

## How to reference case studies

When you cite a case study, tie it to the current finding instead of name-dropping multiple examples. Say: "This is the same pattern as [app]: [specific parallel]."
