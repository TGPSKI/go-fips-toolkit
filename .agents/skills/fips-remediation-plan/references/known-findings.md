# Known Findings Template

This file is populated by running `@fips-crypto-audit/SKILL.md` against a specific set of repositories. The structure below shows the expected format. Replace with actual findings from your audit.

## CRITICAL — Must Fix or Swap

### <component> (ACTUAL CRYPTO | NON-CRYPTO)

- `path/to/file.go` — `md5.New()` for <purpose>
  - **Classification**: ACTUAL CRYPTO | NON-CRYPTO
  - **Fix**: <specific remediation>
  - **Effort**: XS | S | M | L

## WARNING — Should Fix

### <component> (ACTUAL CRYPTO | TEST CODE)

- `path/to/file.go` — SHA-1 for <purpose>
  - **Fix**: <specific remediation>
  - **Effort**: XS | S | M | L

## AUDIT — No Change Needed (Already FIPS-Approved)

Summarize AUDIT findings by category:

| Category | Files | Verdict |
|----------|-------|---------|
| crypto/sha256 for content hashing | N | SHA-256 approved, no change |
| crypto/rand for key gen + certs | N | Legitimate crypto, no change |
| crypto/rsa (2048+ bit keys) | N | FIPS-compliant key sizes, no change |

## PR Sequencing (Recommended Order)

| # | Target | PR Description | Effort | Unblocks |
|---|--------|---------------|--------|----------|
| 1 | <most-shared upstream dep> | <description> | XS | Vendor bumps |
| 2 | <component with actual FIPS violation> | <description> | S | Nothing |
| 3 | <component with non-crypto MD5> | <description> | XS | Nothing |
