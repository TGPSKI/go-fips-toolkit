# Non-Crypto Usage Patterns Reference

Code patterns that indicate a crypto primitive is being used for non-cryptographic purposes. When these patterns are present, the finding is almost certainly NON-CRYPTO and should be swapped to a non-crypto hash or an approved algorithm.

## Content Addressing / Fingerprinting

```go
// SHA-256 for config annotation — NON-CRYPTO
configSum := sha256.Sum256(configStr)
annotations["config-hash"] = fmt.Sprintf("%x", configSum)

// SHA-256 for resource checksum — NON-CRYPTO
return fmt.Sprintf("sha256:%x", sha256.Sum256(data))

// MD5 for struct hashing — NON-CRYPTO
h := md5.New()
io.WriteString(h, fmt.Sprintf("%v", obj))
cacheKey := fmt.Sprintf("%x", h.Sum(nil))
```

**Discriminating signal**: Hash result goes into a string format, map key, annotation, or label. Never used for verification, signing, or encryption.

## Deduplication / Cache Keys

```go
// SHA-256 for event dedup — NON-CRYPTO
hash := sha256.Sum256([]byte(reason + message))
eventName := fmt.Sprintf("event-%s-%s", reason, hex.EncodeToString(hash[:])[:12])

// SHA-256 for profile fingerprinting — NON-CRYPTO
h := sha256.New()
for _, item := range items {
    h.Write([]byte(item.Data))
}
```

**Discriminating signal**: Hash is truncated, used as a suffix, or combined with other identifiers. The algorithm doesn't matter — FNV-1a would work equally well.

## Token / Key Lookup (hash-as-index)

```go
// SHA-256 for bearer token lookup — NON-CRYPTO
h := sha256.Sum256([]byte(tokenValue))
storedName = "sha256~" + base64.RawURLEncoding.EncodeToString(h[0:])
```

**Discriminating signal**: Hash is used as a lookup key or index, not for authentication. SHA-256 is FIPS-approved anyway, so no change needed regardless of intent.

## Session Secret / Key Generation

```go
// crypto/rand for session secrets — LEGITIMATE CRYPTO
const keyLen = sha256.BlockSize
b := make([]byte, keyLen)
rand.Read(b)
```

**Discriminating signal**: `crypto/rand.Read()` generating key material or session secrets is always legitimate crypto.

## Certificate Operations (Test Code)

```go
// RSA key gen in test — TEST CODE, low priority
privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
template := &x509.Certificate{...}
derBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
```

**Discriminating signal**: In `*_test.go` or `test/` directory. Using FIPS-approved algorithms (RSA 2048+, P-256). No change needed.

## UUID Generation (google/uuid)

```go
// MD5 for UUID v3 — NON-CRYPTO, RFC 4122 mandated
func NewMD5(space UUID, data []byte) UUID {
    return NewHash(md5.New(), space, data, 3)
}
```

**Discriminating signal**: UUID v3/v5 generation per RFC 4122. The hash algorithm is part of the UUID spec, not a security choice.

## File Integrity Checksums

```go
// SHA-256 for file checksum — NON-CRYPTO
hash := sha256.New()
io.Copy(hash, file)
return hex.EncodeToString(hash.Sum(nil))
```

**Discriminating signal**: Hashing file contents for integrity verification (not signing). Would work with any hash. SHA-256 is approved anyway.

## SubjectKeyId Computation

```go
// SHA-1 for X.509 SubjectKeyId — NON-CRYPTO (identifier, not signature)
hash := sha1.New()
hash.Write(publicKey.N.Bytes())
subjectKeyId = hash.Sum(nil)
```

**Discriminating signal**: SubjectKeyId is an identifier per RFC 5280 section 4.2.1.2. Not used for authentication. SHA-1 is conventional here but any hash works.

## WebSocket Handshake (x/net)

```go
// SHA-1 for WebSocket Sec-WebSocket-Accept — PROTOCOL-MANDATED
h := sha1.New()
h.Write(nonce)
h.Write([]byte(websocketGUID))
```

**Discriminating signal**: RFC 6455 section 4.2.2 mandates SHA-1 for the WebSocket handshake. Not a security operation.

## Password Hashing (ACTUAL CRYPTO — the exception)

```go
// MD5 for password hashing — ACTUAL CRYPTO, must fix
func aprMD5(password, salt []byte) []byte {
    h := md5.New()
    h.Write(password)
    // ... Apache $apr1$ algorithm ...
}
```

**Discriminating signal**: Hash is used for password verification or authentication. This is the most common case where a CRITICAL finding is a genuine FIPS violation. Fix: migrate to bcrypt, argon2, or PBKDF2.
