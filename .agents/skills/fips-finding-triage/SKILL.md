---
name: fips-finding-triage
description: "Classifies an individual FIPS crypto audit finding as real cryptography or a non-cryptographic use of a crypto primitive, using structured diagnostic reasoning. Follows the abductive triage methodology of resolving coordinate mismatches first, since most findings are non-crypto, then tracing data flow and protocol requirements only when a usage is genuinely ambiguous. Use when an audit surfaces a CRITICAL or WARNING finding that needs classification, when a vendored dependency's crypto usage may not ship in the binary, or when producing evidence for a compliance review."
metadata:
  author: TGPSKI
  version: "1.0"
license: MIT
compatibility: "Go 1.24+ (native FIPS 140-3 module), bash. Operates on findings emitted by the fips-crypto-audit skill plus the Go source under review; no network access required."
---

# FIPS Finding Triage

Structured diagnostic reasoning for classifying individual FIPS crypto audit findings. Determines whether a `crypto/` package usage is actual cryptography or non-cryptographic use of a crypto primitive.

This skill follows the **abductive triage** methodology: resolve coordinate mismatches first (majority of findings are non-crypto), then investigate deeper only when the usage is genuinely ambiguous.

## When to Use

- Audit found a CRITICAL or WARNING finding and you need to classify it
- A finding's context is ambiguous — could be crypto or non-crypto
- Vendor dependency uses crypto and you need to determine if it ships in the binary
- Generating evidence for a compliance review

## Tier 1 — Fast Path (resolves ~80% of findings)

Most FIPS audit findings are coordinate mismatches: code using a crypto primitive for a non-cryptographic purpose. Check these discriminating signals first, in order:

### Check 1: Is it in vendor/ or test code?

| Status | Action |
|--------|--------|
| In `vendor/` and a build-time tool (linter, codegen, analysis) | **FALSE POSITIVE** — not compiled into binary. Close. |
| In `vendor/` and a runtime dependency | Continue to Check 2, but note: fix owner is upstream. |
| In `*_test.go` or `test/` directory | **LOW PRIORITY** — fix during test refactor. Close unless specifically asked. |
| In production code (non-test, non-vendor) | Continue to Check 2. |

### Check 2: What does the surrounding code do?

Read 10-15 lines of context around the crypto call. Look for these discriminating patterns:

| Pattern | Verdict | Confidence |
|---------|---------|-----------|
| Hash result used as map key, annotation, label, or file name | NON-CRYPTO | High |
| Hash result compared for equality (dedup, cache hit) | NON-CRYPTO | High |
| Hash result stored as `sha256:...` prefix string | NON-CRYPTO (content-addressable) | High |
| Hash result used in `fmt.Sprintf("%x", ...)` for display/logging | NON-CRYPTO | High |
| Hash used with `hmac.New()` for request signing or MAC verification | CRYPTO | High |
| Key generated with `rsa.GenerateKey()` or `ecdsa.GenerateKey()` | CRYPTO | High |
| Used inside `tls.Config{}` or `x509.CreateCertificate()` | CRYPTO | High |
| Password hashing (bcrypt, scrypt, argon2, or MD5/SHA-1 for passwords) | CRYPTO | High |
| Result feeds into `cipher.NewGCM()`, `cipher.NewCBCEncrypter()` | CRYPTO | High |

### Check 3: Variable and function naming

Names reveal intent. Check the function name, variable names, and comments:

| Name pattern | Verdict |
|-------------|---------|
| `computeHash`, `configHash`, `specHash`, `contentHash` | NON-CRYPTO |
| `fingerprint`, `checksum`, `digest` (without "verify") | NON-CRYPTO |
| `cacheKey`, `dedup`, `etag`, `annotationHash` | NON-CRYPTO |
| `sign`, `verify`, `encrypt`, `decrypt`, `authenticate` | CRYPTO |
| `seal`, `open`, `mac`, `hmac` (as operation, not just import) | CRYPTO |
| `password`, `credential`, `token` (with hash operation) | CRYPTO |

## Tier 2 — Deep Investigation (only if Tier 1 is inconclusive)

If the fast path doesn't resolve the finding, investigate deeper:

### Step 1: Trace the data flow

```bash
# Find where the hash result is used
rg -n --type go -A 10 '<hash_variable>' <file>
```

Follow the hash output. Where does it go?
- Into a comparison → NON-CRYPTO
- Into a network write or crypto operation → CRYPTO
- Into a struct field or map key → NON-CRYPTO
- Into a signature or MAC → CRYPTO

### Step 2: Check if the algorithm matters

For non-crypto uses, the specific hash algorithm is irrelevant — any hash would work. Ask: "Would replacing MD5 with FNV-1a or CRC32 break the functionality?"

| Answer | Verdict |
|--------|---------|
| No, any hash works | NON-CRYPTO — swap to `hash/fnv` or `crypto/sha256` |
| Yes, must be MD5 specifically | Check why — protocol compat? Then PROTOCOL-MANDATED |
| Yes, must be cryptographically secure | CRYPTO — needs FIPS-approved algorithm |

### Step 3: Check protocol requirements

If the code implements a protocol (SSH, PGP, WebSocket, AWS S3, UUID):

```bash
# Check for RFC references or protocol constants
rg -n -i 'rfc|protocol|spec|standard|compat' <file>
```

| Status | Verdict |
|--------|---------|
| RFC mandates this algorithm (e.g., UUID v3 requires MD5) | PROTOCOL-MANDATED — needs upstream fix or build-tag gate |
| Protocol supports this as legacy option (e.g., SSH 3DES) | PROTOCOL-LEGACY — needs upstream decision |
| No protocol requirement found | Continue investigation |

## Output

For each finding, produce a classification record:

```markdown
### <file>:<line> — <package>.<function>()

- **Classification**: ACTUAL CRYPTO | NON-CRYPTO | PROTOCOL-MANDATED | TEST-ONLY | FALSE-POSITIVE
- **Confidence**: High | Medium | Low
- **Evidence**: <what you observed that led to this classification>
- **Remediation**:
  - ACTUAL CRYPTO → replace with FIPS-approved algorithm
  - NON-CRYPTO → swap to `hash/fnv`, `hash/crc32`, or `crypto/sha256`
  - PROTOCOL-MANDATED → swap or gate behind build tag; document the RFC requirement
  - TEST-ONLY → swap algorithm in test code
  - FALSE-POSITIVE → no action, exclude from scanner
- **Effort**: XS (<15 min) | S (<1 hour) | M (<4 hours) | L (>4 hours)
```

## Evidence Hierarchy

When classifying findings, trust evidence in this order:

| Label | Source | Trust |
|-------|--------|-------|
| DEFINITIVE | Code context: actual function calls and data flow | Highest |
| CONFIG | Variable/function naming, comments, struct tags | High |
| HEURISTIC | Automated pattern matching (non-crypto patterns) | Medium |
| SOCIAL | "Someone said this is fine" | Do not trust — verify |

## Follow-up Skills

- Use `@fips-remediation-plan/SKILL.md` after classifying all findings to generate TODO lists
- Use `@fips-crypto-audit/SKILL.md` to re-audit after fixes to confirm resolution
