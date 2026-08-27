# go-fips-toolkit

Audit, classify, and plan remediation for Go projects migrating to Go's native FIPS 140-3 provider.

Go 1.24+ introduced a native FIPS 140-3 cryptographic module, replacing the CGO/OpenSSL and BoringCrypto models that came before it. Building with `GOFIPS140` enables FIPS mode — approved algorithms use the Go Cryptographic Module, and non-approved algorithms continue to work. For CMVP-validated builds, use a specific frozen version like `GOFIPS140=v1.0.0` (CMVP Certificate #5247).

Go also provides a strict testing mode (`GODEBUG=fips140=only`) that panics on any non-approved crypto call. This catches non-cryptographic uses of crypto primitives — MD5 for checksums, SHA-1 for UUIDs, DES in vendored SSH libraries — that the old CGO/OpenSSL boundary never saw. The Go team explicitly describes `only` mode as a best-effort testing and assessment tool, [not intended for production](https://go.dev/doc/security/fips140).

This toolkit helps you find, classify, and fix those calls before they fail in CI.

## What it does

- **Scans** Go source for every `crypto/` package import (first-party and vendored)
- **Classifies** by FIPS 140-3 risk: CRITICAL, WARNING, AUDIT, INFO
- **Separates** first-party code from vendor dependencies
- **Identifies** non-crypto usage of crypto primitives (the real migration work)
- **Generates** per-component remediation TODO lists with effort estimates
- **Produces** JSON output for downstream tooling

## Quick start

```bash
git clone https://github.com/TGPSKI/go-fips-toolkit.git
cd go-fips-toolkit

# List the repos you want to audit (one org/repo per line)
cat > repos.txt << 'EOF'
myorg/my-service
myorg/my-library
myorg/my-operator
EOF

# Clone and audit
make clone
make audit
```

Results land in `results/`:
- `summary-<timestamp>.txt` — findings by component
- `<component>-<timestamp>.txt` — per-file detail with code context
- `audit-<timestamp>.json` — machine-readable output (with `make audit-json`)

## The problem

Before Go 1.24, FIPS-compliant Go builds routed crypto operations through OpenSSL or BoringCrypto via CGO. The `crypto/` packages were patched to redirect FIPS-approved algorithms (AES, SHA-256, RSA, etc.) to the C library for validation. But non-approved algorithms like MD5, DES, and RC4 were left as pure Go — they never entered the FIPS-validated module. Your code could call `md5.New()` all day for cache keys and checksums because those calls never crossed the enforcement boundary.

Go's strict testing mode (`GODEBUG=fips140=only`) moves the enforcement boundary into the Go runtime. Every call to `crypto/md5`, `crypto/des`, `crypto/rc4`, and restricted calls to `crypto/sha1` will **error or panic** — regardless of whether the call is cryptographic. This catches:

| What breaks | Why it breaks | Is it a FIPS violation? |
|------------|--------------|----------------------|
| `md5.New()` for cache keys | MD5 not FIPS-approved | No — not crypto |
| `sha1.New()` for SubjectKeyId | SHA-1 restricted | No — identifier, not signature |
| UUID v3 generation (google/uuid) | Uses MD5 per RFC 4122 | No — spec-mandated |
| WebSocket handshake (x/net) | Uses SHA-1 per RFC 6455 | No — protocol handshake |
| SSH legacy ciphers (x/crypto) | 3DES, RC4, DSA | Yes — actual crypto |
| htpasswd MD5 password hashing | MD5 for authentication | Yes — actual crypto |

The toolkit tells you which is which.

### Build-time and runtime FIPS controls

Go provides two separate controls. The [Go FIPS 140-3 documentation](https://go.dev/doc/security/fips140) is the authoritative reference.

**`GOFIPS140` (build time)** selects the Go Cryptographic Module version and enables FIPS mode by default. `off` is the default (no FIPS). `latest` enables FIPS mode using the in-tree module. `v1.0.0`, `v1.26.0` select specific frozen versions for CMVP validation. `inprocess` and `certified` are aliases for the latest version that reached the CMVP Modules In Process List or obtained a validation certificate, respectively. Most programs should set this at build time and not touch the runtime flag.

**`GODEBUG=fips140` (runtime)** controls enforcement. Values: `off`, `on`, `only`. It defaults to `on` when built with `GOFIPS140`. Per Go's docs: "Most programs should not set this option directly, and should instead use `GOFIPS140` at build time."

| Mode | What it does | Non-approved algorithms | Use case |
|------|-------------|------------------------|----------|
| `fips140=on` | Approved algorithms use the FIPS-validated module | Still work | **Production** — this is the intended deployment mode |
| `fips140=only` | Same, plus blocks all non-approved algorithms | Panic / error | **CI/testing only** — the Go team calls this "a best effort mode meant for testing, assessment, and debugging" |

Per Go's docs: `fips140=only` "is not intended to be used in production, it is not required by the Security Policy, it introduces crashes and potentially unhandled errors by design, and it may have false positives or false negatives."

There is no annotation, pragma, or build tag to exempt individual calls from `only` mode. Every non-approved `crypto/` call either gets replaced with an approved algorithm (`crypto/sha256`), swapped to a non-crypto hash (`hash/fnv`, `hash/crc32`), or removed.

This toolkit is most useful when preparing for `fips140=only` in CI. If you only need `fips140=on` for production, the audit still helps identify genuine crypto violations, but non-crypto findings become informational.

## Classification

| Class | Meaning | Action |
|-------|---------|--------|
| **CRITICAL** | Algorithm not approved: md5, des, rc4 | Fix or swap |
| **WARNING** | Deprecated or restricted: sha1, dsa | Likely fix |
| **AUDIT** | Approved algorithm, needs intent review | Verify crypto vs non-crypto |
| **INFO** | Legitimate crypto: tls, x509 | No action |
| **XCRYPTO** | golang.org/x/crypto usage | Per-package review |

## Commands

```bash
make clone                                  # Clone repos from repos.txt
make audit                                  # Full audit with vendor summary
make audit-first-party                      # Skip vendor (focus on your code)
make audit-json                             # JSON output for tooling
make audit-component COMPONENT=my-service   # Single component
make clean                                  # Remove results
make clean-repos                            # Remove cloned repos
make help                                   # Show all targets
```

### Direct script usage

```bash
# Clone specific repos
./audit/clone.sh -r myorg/my-service myorg/my-library

# Custom repos and output directories
REPOS_DIR=/tmp/repos OUTPUT_DIR=/tmp/results ./audit/audit-crypto.sh --vendor-summary

# Full clone from file
./audit/clone.sh repos.txt
```

## AI agent skills

The toolkit includes three agent skills compatible with [Cursor](https://cursor.com), [Claude Code](https://docs.anthropic.com/en/docs/claude-code), and any IDE that reads `SKILL.md` files.

| Skill | Pattern | What it does |
|-------|---------|-------------|
| `fips-crypto-audit` | [Directed Workflow](https://github.com/TGPSKI/directed-workflows) | Runs the audit pipeline, analyzes results, does deep inspection on request |
| `fips-remediation-plan` | [Directed Workflow](https://github.com/TGPSKI/directed-workflows) | Generates per-component TODO lists with effort estimates and PR sequencing |
| `fips-finding-triage` | [Abductive Triage](https://github.com/TGPSKI/abductive-triage) | Classifies ambiguous findings as crypto vs non-crypto with structured reasoning |

Skills live in `.agents/skills/` and are symlinked into `.cursor/skills/` and `.claude/skills/` for auto-discovery. Invoke with `@fips-crypto-audit/SKILL.md`.

## What you'll typically find

**Most findings are in vendored dependencies.** The top offenders are ecosystem-wide:

| Dependency | Issue | Crypto? |
|-----------|-------|---------|
| google/uuid | MD5/SHA-1 for UUID v3/v5 | No — RFC 4122 |
| golang.org/x/crypto | 3DES, RC4, DSA in SSH/PGP | Yes — protocol ciphers |
| golang.org/x/tools | MD5/DES/RC4 in stdlib metadata | No — build-time, not in binary |
| golang.org/x/net | SHA-1 in WebSocket handshake | No — RFC 6455 |
| aws/smithy-go | MD5 for Content-MD5 header | No — AWS API requirement |

**First-party findings are almost always non-crypto.** Content hashing, cache keys, config fingerprints, dedup — all using `crypto/sha256` or `crypto/md5` for convenience, not security. SHA-256 calls need no change (already FIPS-approved). MD5 calls need a swap to `sha256` or `hash/fnv`.

**Genuine FIPS violations are rare.** The most common: password hashing with MD5/SHA-1 (e.g., htpasswd implementations) that should use bcrypt or argon2.

## Repository structure

```
go-fips-toolkit/
├── README.md
├── AGENTS.md                              # Agent context
├── Makefile
├── audit/
│   ├── clone.sh                           # Clone repos for audit
│   ├── audit-crypto.sh                    # FIPS crypto scanner
│   └── results/                           # Output (gitignored)
├── repos/                                 # Cloned repos (gitignored)
└── .agents/skills/
    ├── fips-crypto-audit/
    │   ├── SKILL.md
    │   ├── scripts/                       # Symlinks to audit/
    │   └── references/
    │       └── classification-table.md    # Algorithm table + decision tree
    ├── fips-remediation-plan/
    │   ├── SKILL.md
    │   └── references/
    │       └── known-findings.md          # Template for audit results
    └── fips-finding-triage/
        ├── SKILL.md
        └── references/
            └── non-crypto-patterns.md     # Code pattern examples
```

## Requirements

- bash 4+
- [ripgrep](https://github.com/BurntSushi/ripgrep) (`rg`)
- git

## License

MIT

## Author

Tyler Pate ([@TGPSKI](https://github.com/TGPSKI))
