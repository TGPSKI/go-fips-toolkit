# FIPS 140-3 Crypto Classification Reference

## Algorithm Classification

| Package | Class | FIPS 140-3 Status | Common False Positives |
|---------|-------|-------------------|----------------------|
| crypto/md5 | CRITICAL | Not approved | ETags, UUID v3, content checksums, cache keys |
| crypto/des | CRITICAL | Withdrawn 2023 | SSH/PGP legacy protocol support |
| crypto/rc4 | CRITICAL | Never approved | SSH legacy cipher |
| crypto/sha1 | WARNING | Restricted (HMAC-SHA1 OK, signatures not) | Git hashes, SubjectKeyId, UUID v5, WebSocket RFC 6455 |
| crypto/dsa | WARNING | Deprecated FIPS 186-5 | SSH ssh-dss key type, PGP legacy |
| crypto/rand | AUDIT | Approved (DRBG) | Always legitimate — used for key gen, nonces, random bytes |
| crypto/sha256 | AUDIT | Approved | Content-addressable storage, config hash annotations, token hashing |
| crypto/sha512 | AUDIT | Approved | Resource version hashing |
| crypto/hmac | AUDIT | Approved | Integrity checks (may be non-security) |
| crypto/subtle | AUDIT | Approved | ConstantTimeCompare — almost always legit crypto |
| crypto/cipher | AUDIT | Approved | Block cipher modes — almost always legit crypto |
| crypto/aes | AUDIT | Approved | Almost always legit crypto |
| crypto/rsa | AUDIT | Approved (>= 2048 bit) | Key generation in tests |
| crypto/ecdsa | AUDIT | Approved (P-256/384/521) | Test cert generation |
| crypto/ecdh | AUDIT | Approved (P-256/384/521) | Rarely seen outside TLS |
| crypto/ed25519 | AUDIT | Approved (FIPS 186-5) | Legitimate signing |
| crypto/elliptic | AUDIT | Deprecated API | Test code, use crypto/ecdh instead |
| crypto/tls | INFO | N/A (config) | Review cipher suite list for FIPS-only |
| crypto/x509 | INFO | N/A (certs) | Certificate operations, typically legit |

## Remediation Decision Tree

```
Finding detected
├── Is it in vendor/ ?
│   ├── YES → Is the vendor dep a build-time tool (linter, codegen)?
│   │   ├── YES → FALSE POSITIVE — not in binary
│   │   └── NO → Is the crypto usage protocol-mandated (RFC, spec)?
│   │       ├── YES → Needs upstream fix or FIPS policy decision
│   │       └── NO → Is it non-crypto (hashing, checksums)?
│   │           ├── YES → Needs upstream fix (swap to hash/fnv or crypto/sha256)
│   │           └── NO → ACTUAL CRYPTO — needs upstream fix
│   └── Owner: upstream maintainer
├── Is it in test code (*_test.go, test/)?
│   ├── YES → LOW PRIORITY — fix in test refactor
│   └── NO → Continue
├── Is the algorithm FIPS-approved (SHA-256, AES, RSA >= 2048)?
│   ├── YES → NO CHANGE NEEDED under fips140=only
│   └── NO → Continue
├── Is it actual cryptographic use (auth, signing, encryption, MAC)?
│   ├── YES → MUST FIX — replace algorithm or remove feature
│   └── NO → SWAP — replace with hash/fnv, hash/crc32, or crypto/sha256
└── Fix priority: CRITICAL > WARNING > AUDIT
```

## Common Vendor Dependencies With FIPS Findings

These dependencies appear frequently across Go projects. When you see them in audit results, check this table before investigating:

| Dependency | Usage | Crypto? | Fix Path |
|-----------|-------|---------|----------|
| google/uuid | MD5 for UUID v3, SHA-1 for UUID v5 | NO — RFC 4122 | Upstream fix or use v4 UUIDs |
| golang.org/x/crypto | SSH: 3DES, RC4, HMAC-SHA1, DSA. PGP: 3DES, MD5, SHA-1, DSA | YES — protocol ciphers | Go team design decision |
| golang.org/x/tools | Stdlib metadata catalogs, build-time analysis | NO — not in binary | FALSE POSITIVE — exclude from scanners |
| golang.org/x/net | SHA-1 for WebSocket RFC 6455 handshake | NO — protocol handshake | Upstream fix |
| aws/smithy-go | MD5 for Content-MD5 HTTP header | NO — AWS API requirement | Wait for SDK release |
