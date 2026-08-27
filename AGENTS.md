# go-fips-toolkit

FIPS 140-3 crypto compliance audit, remediation planning, and finding triage for Go projects migrating to Go's native FIPS provider (`GOFIPS140`).

## Repository structure

```
go-fips-toolkit/
├── AGENTS.md                           # You are here
├── Makefile                            # make clone, make audit, make help
├── audit -> .agents/skills/fips-crypto-audit/scripts/
│                                       # Symlink; skill scripts are canonical
├── results/                            # Audit output (timestamped, gitignored)
├── repos/                              # Cloned repositories (gitignored)
└── .agents/skills/
    ├── fips-crypto-audit/              # Run audits, classify findings
    │   ├── SKILL.md
    │   ├── scripts/                    # Canonical audit and clone scripts
    │   └── references/
    │       └── classification-table.md
    ├── fips-remediation-plan/          # Generate component TODO lists
    │   ├── SKILL.md
    │   └── references/
    │       └── known-findings.md       # Template — populated per-project
    └── fips-finding-triage/            # Classify individual ambiguous findings
        ├── SKILL.md
        └── references/
            └── non-crypto-patterns.md
```

## Quick start

```bash
# Clone repos (pass a repos.txt file or use -r)
./audit/clone.sh repos.txt

# Run full audit with vendor summary
./audit/audit-crypto.sh --vendor-summary --json

# First-party only (skip vendor noise)
./audit/audit-crypto.sh --first-party-only

# Single component
./audit/audit-crypto.sh --component my-service
```

## Skills

| Skill | Pattern | Purpose |
|-------|---------|---------|
| `fips-crypto-audit` | [Directed Workflow](https://github.com/TGPSKI/directed-workflows) | Run audits, clone repos, classify findings, generate reports |
| `fips-remediation-plan` | [Directed Workflow](https://github.com/TGPSKI/directed-workflows) | Generate per-component remediation TODO lists with effort estimates and PR sequencing |
| `fips-finding-triage` | [Abductive Triage](https://github.com/TGPSKI/abductive-triage) | Classify individual findings as crypto vs non-crypto using structured diagnostic reasoning |

Invoke a skill by referencing its SKILL.md: `@fips-crypto-audit/SKILL.md`

## Context

Go 1.24+ introduced a native FIPS 140-3 cryptographic module, replacing the CGO/OpenSSL and BoringCrypto models. Two runtime enforcement levels exist (see [Go FIPS 140-3 docs](https://go.dev/doc/security/fips140)):

- **`fips140=on`** (production) — approved algorithms use the FIPS-validated module; non-approved algorithms still work.
- **`fips140=only`** (CI/testing) — same, plus blocks all non-approved algorithms. The Go team describes this as "a best effort mode meant for testing, assessment, and debugging" — not intended for production, not required by the Security Policy.

Build with `GOFIPS140=v1.0.0` (the module snapshot covered by CMVP Certificate #5247; `GOFIPS140=certified` becomes an alias in Go 1.27 / 1.26.3 / 1.25.10). Set `GODEBUG=fips140=only` in CI to catch non-approved algorithm usage before it ships.

This toolkit automates the audit, classification, and remediation planning for that migration. It is most useful when preparing for `fips140=only` in CI.
