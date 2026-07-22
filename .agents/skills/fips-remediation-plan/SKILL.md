---
name: fips-remediation-plan
description: "Generates component-specific FIPS remediation TODO lists from crypto audit results, with effort estimates and suggested PR sequencing. A directed workflow following the Inspect-Decide-Generate pattern, splitting findings into must-fix, primitive swaps, no-change-needed, and upstream dependencies. Use after a FIPS crypto audit when a component team asks what they need to fix, when planning sprint work for a FIPS migration, or when writing remediation PR descriptions."
metadata:
  author: TGPSKI
  version: "1.0"
license: MIT
compatibility: "Go 1.24+ (native FIPS 140-3 module), bash. Consumes audit/results/summary-*.txt produced by the fips-crypto-audit skill; no network access required."
---

# FIPS Remediation Plan

Generate component-specific remediation TODO lists from FIPS crypto audit results, with effort estimates and PR sequencing.

This is a **directed workflow** following the Inspect-Decide-Generate pattern.

## When to Use

- After running `@fips-crypto-audit/SKILL.md` and getting results
- When a component team asks "what do I need to fix?"
- When planning sprint work for FIPS migration
- When generating PR descriptions for remediation work

## Inspect

### 1. Find audit results

```bash
ls -lt audit/results/summary-*.txt | head -3
```

If no results exist, tell the user to run `@fips-crypto-audit/SKILL.md` first.

### 2. Read the summary

Read the most recent summary file to understand the scope.

### 3. Determine target

Ask the user:

| Question | Default |
|----------|---------|
| Which component(s)? | All with CRITICAL or WARNING findings |
| Include vendor findings? | First-party only (vendor needs upstream PRs) |
| Output format? | Markdown TODO list |

## Decide

For each component, read its detail file and classify every first-party finding:

| Finding Class | Status | Action |
|--------------|--------|--------|
| CRITICAL first-party, actual crypto | `must-fix` | Replace algorithm or remove feature |
| CRITICAL first-party, non-crypto | `swap` | Replace with `hash/fnv`, `hash/crc32`, or `crypto/sha256` |
| WARNING first-party, test code | `low-priority` | Fix in test refactor |
| WARNING first-party, production | `should-fix` | Swap algorithm |
| AUDIT first-party, SHA-256/AES/RSA>=2048 | `no-change` | Already FIPS-approved |
| AUDIT first-party, crypto/rand | `no-change` | Legitimate crypto RNG |
| Vendor CRITICAL, org-owned | `upstream-pr` | File PR against shared library |
| Vendor CRITICAL, external | `track` | File issue, track upstream |

## Generate

### For each component with findings, produce:

```markdown
## <component-name> FIPS Remediation

### Must Fix (blocks fips140=only)

- [ ] `path/to/file.go:42` — md5.New() for password hashing
  - **Why**: Actual cryptographic use of non-FIPS algorithm
  - **Fix**: Replace with bcrypt or SHA-256 based password hash
  - **Effort**: S (< 1 hour)
  - **PR**: Standalone PR, no dependencies

### Swap (non-crypto usage of crypto primitives)

- [ ] `path/to/file.go:88` — md5.New() for content fingerprinting
  - **Why**: Non-cryptographic use, will fail under fips140=only
  - **Fix**: Replace with `hash/fnv` or `crypto/sha256` (already FIPS-approved)
  - **Effort**: XS (< 15 min)

### No Change Needed

- `path/to/file.go:120` — sha256.Sum256() for config annotation hash
  - SHA-256 is FIPS-approved. No action required.

### Upstream Dependencies

- [ ] <shared-library> — <description of finding>
  - **Track**: [link to issue/PR if exists]
  - **After fix**: Run `go get` + `go mod vendor` to pull fix
```

### PR Sequencing

Generate a suggested PR order:

| Order | PR | Components | Depends On |
|-------|-----|-----------|-----------|
| 1 | Shared library: swap non-FIPS hash to SHA-256 | All consumers | Nothing |
| 2 | Service with actual FIPS violation | That service | Nothing |
| 3 | Service with non-crypto MD5 usage | That service | Nothing |
| N | Vendor bumps across all consumers | All | PR #1 merged |

### Effort Summary

For each component, produce a one-line effort estimate:

```
<service-a>:   1 must-fix, 1 swap → ~2 hours
<service-b>:   2 swap → ~30 min
<service-c>:   1 swap → ~15 min
All others:    vendor bumps only → ~15 min each after upstream PRs merge
```

## Follow-up Skills

- Use `@fips-finding-triage/SKILL.md` to investigate ambiguous findings before classifying
- Use `@fips-crypto-audit/SKILL.md` to re-audit after fixes are applied
