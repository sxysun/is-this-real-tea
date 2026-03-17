#!/usr/bin/env bash
# is-this-real-tea: Automated TEE Audit Checks
# Usage: ./tools/audit-checks.sh /path/to/repo
#
# Quick automated scan for common dstack/TEE vulnerabilities.
# For deeper analysis, use the full agent-guided audit (AGENT.md).

set -euo pipefail

REPO_PATH="${1:-.}"
cd "$REPO_PATH"

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

section() { echo -e "\n## $1\n---"; }
warn()    { echo -e "${YELLOW}[!] $1${NC}"; }
critical(){ echo -e "${RED}[!!!] $1${NC}"; }
ok()      { echo -e "${GREEN}[ok] $1${NC}"; }
info()    { echo "   $1"; }

# Exclusion patterns
EXCLUDES="--exclude-dir=node_modules --exclude-dir=dist --exclude-dir=build --exclude-dir=.git --exclude=*.min.js --exclude=bundle.js --exclude=*.bundle.js"

echo "=========================================="
echo "is-this-real-tea: $(basename "$PWD")"
echo "=========================================="

# ============================================
section "1. OPERATOR-CONFIGURABLE URLs (CRITICAL)"
# ============================================

echo "### Configurable URLs in code:"
results=$(grep -rl -i 'base_url\|api_url\|endpoint\|_url' --include='*.py' --include='*.ts' --include='*.js' $EXCLUDES . 2>/dev/null || true)
if [[ -n "$results" ]]; then
    echo "$results" | head -10
    grep -rn -i 'base_url\|api_url\|endpoint\|_url' --include='*.py' --include='*.ts' --include='*.js' $EXCLUDES . 2>/dev/null | head -20
    warn "Found configurable URLs - verify these are hardcoded in docker-compose.yml"
else
    ok "No obvious configurable URLs found"
fi

echo ""
echo "### Environment variable loading:"
results=$(grep -rl -i 'BaseSettings\|pydantic_settings\|environ\|getenv\|process\.env\|dotenv' --include='*.py' --include='*.ts' --include='*.js' $EXCLUDES . 2>/dev/null || true)
if [[ -n "$results" ]]; then
    echo "$results" | head -10
    warn "Environment loading detected - check what's configurable"
else
    ok "No environment loading patterns found"
fi

echo ""
echo "### docker-compose.yml \${VAR} patterns:"
if [[ -f docker-compose.yml ]]; then
    vars=$(grep -E '\$\{.*\}|\$[A-Z_]+' docker-compose.yml 2>/dev/null || true)
    if [[ -n "$vars" ]]; then
        echo "$vars" | head -20
        warn "Operator-configurable values found in compose"
    else
        ok "No \${VAR} patterns in compose"
    fi
    echo ""
    echo "Hardcoded URLs:"
    grep -E '^\s*-\s+[A-Z_]+=https?://' docker-compose.yml 2>/dev/null | head -10 || echo "   None found"
else
    warn "No docker-compose.yml found"
fi

# ============================================
section "2. ATTESTATION CODE"
# ============================================

echo "### Attestation-related code:"
results=$(grep -rl -i 'attestation\|verify.*quote\|tdx\|report_data\|dstack-sdk\|getKey' --include='*.py' --include='*.ts' --include='*.js' $EXCLUDES . 2>/dev/null || true)
if [[ -n "$results" ]]; then
    echo "$results" | head -10
    ok "Attestation code found - review implementation"
else
    warn "No attestation code found - TEE may be decoration"
fi

echo ""
echo "### Signature verification:"
results=$(grep -rl 'recover_message\|verify_signature\|ecdsa\|secp256k1\|eth_account' --include='*.py' --include='*.ts' --include='*.js' $EXCLUDES . 2>/dev/null || true)
if [[ -n "$results" ]]; then
    echo "$results" | head -10
    ok "Signature verification found"
else
    info "No signature verification found"
fi

# ============================================
section "3. RED FLAGS"
# ============================================

echo "### Known issue / workaround comments:"
results=$(grep -rn -i 'known issue\|known bug\|workaround' --include='*.py' --include='*.ts' --include='*.js' $EXCLUDES . 2>/dev/null || true)
if [[ -n "$results" ]]; then
    echo "$results" | head -10
    critical "Found 'known issue' comments - review carefully"
else
    ok "No 'known issue' comments"
fi

echo ""
echo "### Hash mismatch acceptance:"
results=$(grep -rn -i 'mismatch\|ignore.*hash\|skip.*verif\|bypass' --include='*.py' --include='*.ts' --include='*.js' $EXCLUDES . 2>/dev/null || true)
if [[ -n "$results" ]]; then
    echo "$results" | head -10
    critical "Potential hash mismatch acceptance"
else
    ok "No hash mismatch acceptance"
fi

echo ""
echo "### Development fallbacks:"
results=$(grep -rn 'dev_mode\|development_mode\|_dev_\|fallback\|mock_\|fake_\|stub_' --include='*.py' --include='*.ts' --include='*.js' $EXCLUDES . 2>/dev/null || true)
if [[ -n "$results" ]]; then
    echo "$results" | head -10
    warn "Development fallbacks found - verify not reachable in production"
else
    ok "No development fallbacks"
fi

echo ""
echo "### Disabled verification:"
results=$(grep -rn 'verify.*=.*False\|skip.*verify\|no.*verify\|disable.*check' --include='*.py' --include='*.ts' --include='*.js' $EXCLUDES . 2>/dev/null || true)
if [[ -n "$results" ]]; then
    echo "$results" | head -10
    critical "Potentially disabled verification"
else
    ok "No disabled verification flags"
fi

# ============================================
section "4. BUILD REPRODUCIBILITY"
# ============================================

for df in Dockerfile Dockerfile.*; do
    [[ -f "$df" ]] || continue
    echo "File: $df"
    grep -E '^FROM.*@sha256:' "$df" >/dev/null 2>&1 && ok "Base image pinned by digest" || warn "Base image NOT pinned by digest"
    grep -q 'SOURCE_DATE_EPOCH' "$df" 2>/dev/null && ok "SOURCE_DATE_EPOCH set" || warn "SOURCE_DATE_EPOCH not set"
    grep -q 'apt-get update' "$df" 2>/dev/null && warn "apt-get update without snapshot pinning" || true
    echo ""
done

if [[ -d .github/workflows ]]; then
    grep -rl 'rewrite-timestamp\|SOURCE_DATE_EPOCH' .github/workflows/ 2>/dev/null && ok "Reproducibility flags in CI" || warn "No reproducibility flags in CI"
fi

# ============================================
section "5. SECRETS"
# ============================================

echo "### Secret-related code:"
grep -rn -i 'secret\|api_key\|token\|password\|credential' --include='*.py' --include='*.ts' --include='*.js' $EXCLUDES . 2>/dev/null | grep -v 'test\|mock\|example' | head -15 || echo "   None found"

# ============================================
section "6. HTTP CLIENTS & OUTBOUND DATA"
# ============================================

echo "### HTTP clients:"
grep -rn 'httpx\|requests\.\|aiohttp\|fetch(\|axios\.\|AsyncOpenAI\|OpenAI' --include='*.py' --include='*.ts' --include='*.js' $EXCLUDES . 2>/dev/null | head -15 || echo "   None found"

# ============================================
section "SUMMARY"
# ============================================

echo ""
echo "Automated scan complete. Manual review still needed for:"
echo "1. Trace each configurable URL to understand data flow"
echo "2. Check attestation binding (signing key <-> TDX quote)"
echo "3. Review 'known issue' comments in context"
echo "4. Trace user data from entry to external services"
echo "5. Verify docker-compose.yml hardcodes critical URLs"
echo ""
echo "For full agentic audit, use: AGENT.md"
echo "=========================================="
