---
name: fips-crypto-audit
description: "Runs a FIPS 140-3 crypto compliance audit across Go repositories, classifying every crypto/ import by risk and generating per-component reports. Separates first-party code from vendored dependencies and flags non-cryptographic uses of crypto primitives that break under GODEBUG=fips140=only. Use when auditing Go services for FIPS compliance, assessing new repos before adding them to FIPS CI, re-running an audit after vendor bumps, or generating evidence for compliance documentation."
metadata:
  author: TGPSKI
  version: "1.0"
license: MIT
compatibility: "Go 1.24+ (native FIPS 140-3 module), bash, standard POSIX tooling. Operates on Go source trees cloned into repos/; no network access required beyond the initial clone step."
---

# FIPS Crypto Audit

Run a FIPS 140-3 crypto compliance audit against Go repositories, classify findings, and generate reports.

## When to Use

- Auditing Go services for FIPS compliance before running `GODEBUG=fips140=only` in CI
- Assessing new Go repos for crypto usage before adding to FIPS CI
- Re-running audits after upstream vendor bumps to check delta
- Generating evidence for compliance documentation

## Inspect

1. Check if repos are already cloned:

```bash
ls repos/ 2>/dev/null | wc -l
```

2. Check for existing audit results:

```bash
ls audit/results/summary-*.txt 2>/dev/null | tail -5
```

3. Determine the audit scope. Ask the user:

| Question | Default |
|----------|---------|
| Which repos to audit? | All repos in `repos/` (or pass a `repos.txt`) |
| First-party only or full (including vendor)? | Full |
| Include vendor dependency summary? | Yes |
| Generate JSON output for downstream tools? | Yes |

## Decide

Based on the scope, determine which scripts to run:

| Status | Action |
|--------|--------|
| Repos not cloned | Run `./audit/clone.sh` first |
| Repos cloned, no recent audit | Run full audit |
| Repos cloned, recent audit exists | Ask user: re-run or analyze existing? |
| Single component requested | Run `./audit/audit-crypto.sh --component <name>` |

## Generate

### Phase 1: Clone repos (if needed)

```bash
# From a repos.txt file
./audit/clone.sh repos.txt

# Specific repos
./audit/clone.sh -r myorg/my-service myorg/my-library
```

### Phase 2: Run the audit

```bash
# Full audit with vendor summary and JSON
./audit/audit-crypto.sh --vendor-summary --json

# First-party only (skip vendor noise)
./audit/audit-crypto.sh --first-party-only --json

# Single component deep dive
./audit/audit-crypto.sh --component my-service --json
```

### Phase 3: Analyze results

After the audit completes, read the summary and detail files. Present findings to the user organized by:

1. **First-party CRITICAL findings** — these need immediate attention
2. **First-party WARNING findings** — likely need fixes
3. **First-party AUDIT findings** — classify as crypto vs non-crypto
4. **Vendor dependency hotspots** — identify upstream coordination needs
5. **Grand totals** — first-party vs vendor split

### Phase 4: Deep inspection (if requested)

For each first-party CRITICAL/WARNING finding, do manual inspection:

```bash
# Show the actual code context around the finding
rg -n --type go -B 3 -A 5 'md5\.' repos/<component>/ --glob '!vendor/**'
```

Classify each finding as:
- **ACTUAL CRYPTO** — real cryptographic operation using non-FIPS algorithm → must fix
- **NON-CRYPTO** — hash used for content addressing, caching, dedup → swap algorithm
- **TEST CODE** — only in test files → low priority
- **PROTOCOL-MANDATED** — required by an RFC or protocol spec → needs upstream fix

## Output

The audit produces:
- `audit/results/summary-<timestamp>.txt` — human-readable summary
- `audit/results/<component>-<timestamp>.txt` — per-component detail files
- `audit/results/audit-<timestamp>.json` — machine-readable JSON (with `--json`)

## Follow-up Skills

- Use `@fips-remediation-plan/SKILL.md` to generate component-specific TODO lists from audit results
- Use `@fips-finding-triage/SKILL.md` to investigate and classify individual ambiguous findings
