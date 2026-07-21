#!/usr/bin/env bash
set -euo pipefail

# audit-crypto.sh — FIPS 140-3 crypto compliance audit for Go repositories
#
# Scans Go source for crypto/ package usage and classifies by FIPS compliance risk.
# Separates first-party code from vendored dependencies for actionability.
#
# Usage:
#   ./audit/audit-crypto.sh                              # Audit all repos in ./repos/
#   ./audit/audit-crypto.sh --repos-dir /path/to/repos   # Custom repos location
#   ./audit/audit-crypto.sh --component my-service              # Single component
#   ./audit/audit-crypto.sh --first-party-only            # Skip vendor findings
#   ./audit/audit-crypto.sh --vendor-summary              # Add top vendor dep analysis
#   ./audit/audit-crypto.sh --json                        # JSON output for agent consumption
#
# Environment:
#   REPOS_DIR     Override repos location (default: ./repos)
#   OUTPUT_DIR    Override output location (default: ./audit/results)
#
# Classification:
#   CRITICAL  — algorithm not approved in FIPS 140-3 (md5, des, rc4)
#   WARNING   — deprecated or conditionally approved (sha1, dsa, small RSA keys)
#   AUDIT     — approved algorithm but needs human review for non-crypto usage
#   INFO      — likely legitimate crypto (tls, x509)
#   XCRYPTO   — golang.org/x/crypto usage, needs per-package review

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPOS_DIR="${REPOS_DIR:-$PROJECT_DIR/repos}"
OUTPUT_DIR="${OUTPUT_DIR:-$PROJECT_DIR/audit/results}"

FIRST_PARTY_ONLY=false
VENDOR_SUMMARY=false
JSON_OUTPUT=false
COMPONENT=""

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repos-dir)       REPOS_DIR="$2"; shift 2 ;;
      --output-dir)      OUTPUT_DIR="$2"; shift 2 ;;
      --component)       COMPONENT="$2"; shift 2 ;;
      --first-party-only) FIRST_PARTY_ONLY=true; shift ;;
      --vendor-summary)  VENDOR_SUMMARY=true; shift ;;
      --json)            JSON_OUTPUT=true; shift ;;
      -h|--help)         usage; exit 0 ;;
      *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
  done
}

usage() {
  head -20 "$0" | grep '^#' | sed 's/^# *//'
}

# --- FIPS 140-3 classification tables ---

declare -A CRYPTO_CLASS=(
  ["crypto/md5"]="CRITICAL"
  ["crypto/des"]="CRITICAL"
  ["crypto/rc4"]="CRITICAL"
  ["crypto/sha1"]="WARNING"
  ["crypto/dsa"]="WARNING"
  ["crypto/rand"]="AUDIT"
  ["crypto/sha256"]="AUDIT"
  ["crypto/sha512"]="AUDIT"
  ["crypto/hmac"]="AUDIT"
  ["crypto/subtle"]="AUDIT"
  ["crypto/cipher"]="AUDIT"
  ["crypto/aes"]="AUDIT"
  ["crypto/rsa"]="AUDIT"
  ["crypto/ecdsa"]="AUDIT"
  ["crypto/ecdh"]="AUDIT"
  ["crypto/ed25519"]="AUDIT"
  ["crypto/elliptic"]="AUDIT"
  ["crypto/tls"]="INFO"
  ["crypto/x509"]="INFO"
  ["crypto/x509/pkix"]="INFO"
)

declare -A CRYPTO_REASON=(
  ["crypto/md5"]="MD5 not approved in FIPS 140-3. Common non-crypto uses: ETags, checksums, legacy protocol compat."
  ["crypto/des"]="DES/3DES withdrawn from FIPS 140-3 after 2023. Should not appear in new code."
  ["crypto/rc4"]="RC4 never FIPS-approved. Should not appear in any path."
  ["crypto/sha1"]="SHA-1 restricted in FIPS 140-3 (allowed for HMAC-SHA1 only, not signatures)."
  ["crypto/dsa"]="DSA deprecated in FIPS 186-5. Should not appear in new signing code."
  ["crypto/rand"]="FIPS-approved DRBG required. Check: crypto keys/nonces, or UUIDs/request-IDs?"
  ["crypto/sha256"]="SHA-256 approved. Check: crypto signing, or content-addressing/caching?"
  ["crypto/sha512"]="SHA-512 approved. Check: crypto use or content fingerprinting?"
  ["crypto/hmac"]="HMAC approved. Check: security-critical MAC, or non-security integrity?"
  ["crypto/subtle"]="constant-time compare. Almost always legitimate crypto."
  ["crypto/cipher"]="Block cipher modes. Almost always legitimate crypto."
  ["crypto/aes"]="AES approved. Almost always legitimate crypto."
  ["crypto/rsa"]="RSA approved if key >= 2048 bits. fips140=only rejects < 2048."
  ["crypto/ecdsa"]="ECDSA approved for P-256, P-384, P-521. Check curve selection."
  ["crypto/ecdh"]="ECDH approved for P-256, P-384, P-521. Check curve selection."
  ["crypto/ed25519"]="Ed25519 approved in FIPS 186-5. Likely legitimate."
  ["crypto/elliptic"]="Deprecated API (use crypto/ecdh). Check for direct curve operations."
  ["crypto/tls"]="TLS configuration. Review cipher suite selection for FIPS-only suites."
  ["crypto/x509"]="Certificate operations. Typically legitimate."
  ["crypto/x509/pkix"]="ASN.1 structures for certificates. Typically legitimate."
)

NON_CRYPTO_PATTERNS=(
  'etag'
  'checksum'
  'fingerprint'
  'content.?hash'
  'cache.?key'
  'uuid'
  'request.?id'
  'trace.?id'
  'correlation.?id'
  'nonce.*non'
  'idempotency'
  'dedup'
  'digest.*file'
  'hash.*path'
  'hash.*name'
  'hash.*key.*cache'
  'annotation'
  'config.*sum'
  'spec.*hash'
)

# --- Scanning functions ---

scan_crypto_imports() {
  local repo_dir="$1"
  local detail_file="$2"
  local -n _counts=$3
  local -n _pkg_counts=$4

  for pkg in "${!CRYPTO_CLASS[@]}"; do
    local class="${CRYPTO_CLASS[$pkg]}"
    local import_pattern="\"$pkg\""

    local matches
    if [[ "$FIRST_PARTY_ONLY" == "true" ]]; then
      matches=$(rg -l --type go "$import_pattern" "$repo_dir" --glob '!vendor/**' --glob '!**/vendor/**' 2>/dev/null || true)
    else
      matches=$(rg -l --type go "$import_pattern" "$repo_dir" 2>/dev/null || true)
    fi
    [[ -z "$matches" ]] && continue

    local file_count
    file_count=$(echo "$matches" | wc -l)
    _counts[$class]=$(( ${_counts[$class]} + file_count ))
    _pkg_counts[$pkg]=$file_count

    {
      echo ""
      echo "--- $pkg [$class] ($file_count files) ---"
      echo "Reason: ${CRYPTO_REASON[$pkg]}"
      echo ""
    } >> "$detail_file"

    while IFS= read -r file; do
      local rel_file="${file#"$repo_dir"}"
      local is_vendor="false"
      [[ "$rel_file" == vendor/* ]] && is_vendor="true"

      echo "  [$( [[ "$is_vendor" == "true" ]] && echo "VENDOR" || echo "FIRST-PARTY" )] $rel_file" >> "$detail_file"

      local short="${pkg##*/}"
      rg -n --type go -e "${short}\." -e "$import_pattern" "$file" 2>/dev/null | head -20 | while IFS= read -r line; do
        echo "    $line" >> "$detail_file"
      done

      if [[ "$class" == "CRITICAL" || "$class" == "WARNING" || "$class" == "AUDIT" ]]; then
        local context
        context=$(rg -i -C 3 --type go "${short}\." "$file" 2>/dev/null | tr '\n' ' ' || true)
        for pattern in "${NON_CRYPTO_PATTERNS[@]}"; do
          if echo "$context" | rg -iq "$pattern" 2>/dev/null; then
            echo "    ^^^ LIKELY NON-CRYPTO (matched heuristic: $pattern)" >> "$detail_file"
            break
          fi
        done
      fi

      echo "" >> "$detail_file"
    done <<< "$matches"
  done
}

scan_xcrypto() {
  local repo_dir="$1"
  local detail_file="$2"
  local -n _counts=$3

  local matches
  if [[ "$FIRST_PARTY_ONLY" == "true" ]]; then
    matches=$(rg -l --type go '"golang.org/x/crypto' "$repo_dir" --glob '!vendor/**' --glob '!**/vendor/**' 2>/dev/null || true)
  else
    matches=$(rg -l --type go '"golang.org/x/crypto' "$repo_dir" 2>/dev/null || true)
  fi
  [[ -z "$matches" ]] && return

  local count
  count=$(echo "$matches" | wc -l)
  _counts[XCRYPTO]=$count

  {
    echo ""
    echo "--- golang.org/x/crypto [XCRYPTO] ($count files) ---"
    echo "Reason: Extended crypto packages. Each sub-package needs individual FIPS assessment."
    echo ""
  } >> "$detail_file"

  local xcrypto_pkgs
  if [[ "$FIRST_PARTY_ONLY" == "true" ]]; then
    xcrypto_pkgs=$(rg --type go -o '"golang.org/x/crypto/[^"]+' "$repo_dir" --glob '!vendor/**' --glob '!**/vendor/**' 2>/dev/null | \
      sed 's/.*"golang.org\/x\/crypto\///' | sort -u || true)
  else
    xcrypto_pkgs=$(rg --type go -o '"golang.org/x/crypto/[^"]+' "$repo_dir" 2>/dev/null | \
      sed 's/.*"golang.org\/x\/crypto\///' | sort -u || true)
  fi

  if [[ -n "$xcrypto_pkgs" ]]; then
    echo "  Sub-packages:" >> "$detail_file"
    echo "$xcrypto_pkgs" | while IFS= read -r xpkg; do
      echo "    x/crypto/$xpkg" >> "$detail_file"
    done
    echo "" >> "$detail_file"
  fi

  while IFS= read -r file; do
    local rel_file="${file#"$repo_dir"}"
    local marker="FIRST-PARTY"
    [[ "$rel_file" == vendor/* ]] && marker="VENDOR"
    echo "  [$marker] $rel_file" >> "$detail_file"
  done <<< "$matches"
}

scan_small_rsa_keys() {
  local repo_dir="$1"
  local detail_file="$2"
  local -n _counts=$3

  local matches
  matches=$(rg -n --type go -e 'rsa\.GenerateKey.*1024' -e 'rsa\.GenerateKey.*512' -e 'KeySize.*1024' "$repo_dir" 2>/dev/null || true)
  [[ -z "$matches" ]] && return

  {
    echo ""
    echo "--- SMALL RSA KEY SIZES DETECTED [CRITICAL] ---"
    echo "$matches"
  } >> "$detail_file"
  _counts[CRITICAL]=$(( ${_counts[CRITICAL]} + $(echo "$matches" | wc -l) ))
}

scan_math_rand_mixing() {
  local repo_dir="$1"
  local detail_file="$2"

  local matches
  matches=$(rg -l --type go '"math/rand' "$repo_dir" 2>/dev/null || true)
  [[ -z "$matches" ]] && return

  echo "" >> "$detail_file"
  echo "--- math/rand usage (check: should any use crypto/rand?) ---" >> "$detail_file"
  while IFS= read -r file; do
    local rel_file="${file#"$repo_dir"}"
    if rg -q '"crypto/' "$file" 2>/dev/null; then
      echo "  [MIXED] $rel_file (imports both math/rand and crypto/)" >> "$detail_file"
    else
      echo "  [OK]    $rel_file (math/rand only)" >> "$detail_file"
    fi
  done <<< "$matches"
}

# --- First-party vs vendor split ---

compute_fp_split() {
  local repo_dir="$1"
  local -n _fp_crit=$2
  local -n _fp_warn=$3
  local -n _fp_audit=$4

  for pkg in "${!CRYPTO_CLASS[@]}"; do
    local class="${CRYPTO_CLASS[$pkg]}"
    local fp_matches
    fp_matches=$(rg -l --type go "\"$pkg\"" "$repo_dir" --glob '!vendor/**' --glob '!**/vendor/**' 2>/dev/null || true)
    [[ -z "$fp_matches" ]] && continue
    local count
    count=$(echo "$fp_matches" | wc -l)
    case "$class" in
      CRITICAL) _fp_crit=$(( _fp_crit + count )) ;;
      WARNING)  _fp_warn=$(( _fp_warn + count )) ;;
      AUDIT)    _fp_audit=$(( _fp_audit + count )) ;;
    esac
  done
}

# --- Vendor summary ---

generate_vendor_summary() {
  local summary_file="$1"

  {
    echo ""
    echo "============================================================"
    echo "TOP VENDOR DEPENDENCIES BY FIPS FINDING COUNT"
    echo "============================================================"
    echo ""
  } >> "$summary_file"

  local -A vendor_findings=()

  for repo_dir in "$REPOS_DIR"/*/; do
    [[ -d "$repo_dir" ]] || continue
    for pkg in "crypto/md5" "crypto/des" "crypto/rc4" "crypto/sha1" "crypto/dsa"; do
      local files
      files=$(rg -l --type go "\"$pkg\"" "$repo_dir/vendor/" 2>/dev/null || true)
      [[ -z "$files" ]] && continue
      while IFS= read -r f; do
        local rel="${f#*vendor/}"
        local mod
        mod=$(echo "$rel" | awk -F/ '{
          if ($1 ~ /\.(com|org|io|net|dev)$/) {
            if ($3 ~ /^v[0-9]/) print $1"/"$2
            else print $1"/"$2"/"$3
          }
          else print $1"/"$2
        }')
        vendor_findings[$mod]=$(( ${vendor_findings[$mod]:-0} + 1 ))
      done <<< "$files"
    done
  done

  for mod in $(for k in "${!vendor_findings[@]}"; do echo "$k ${vendor_findings[$k]}"; done | sort -k2 -rn | head -15 | awk '{print $1}'); do
    echo "  ${vendor_findings[$mod]} findings — $mod" >> "$summary_file"
  done
}

# --- JSON output ---

emit_json_component() {
  local name="$1"
  local -n _jc=$2
  local fp_crit="$3"
  local fp_warn="$4"
  local fp_audit="$5"

  printf '  {"name":"%s","critical":%d,"warning":%d,"audit":%d,"info":%d,"xcrypto":%d,"fpCritical":%d,"fpWarning":%d,"fpAudit":%d}' \
    "$name" "${_jc[CRITICAL]}" "${_jc[WARNING]}" "${_jc[AUDIT]}" "${_jc[INFO]}" "${_jc[XCRYPTO]}" \
    "$fp_crit" "$fp_warn" "$fp_audit"
}

# --- Main ---

header() {
  local msg="$1" file="$2"
  {
    echo "============================================================"
    echo "$msg"
    echo "============================================================"
  } >> "$file"
}

main() {
  parse_args "$@"
  mkdir -p "$OUTPUT_DIR"

  local TIMESTAMP
  TIMESTAMP=$(date +%Y%m%d-%H%M%S)
  local SUMMARY="$OUTPUT_DIR/summary-$TIMESTAMP.txt"
  local JSON_FILE="$OUTPUT_DIR/audit-$TIMESTAMP.json"

  : > "$SUMMARY"

  {
    echo "FIPS 140-3 Crypto Audit — Go Repositories"
    echo "Generated: $(date -Iseconds)"
    echo "Mode: $( [[ "$FIRST_PARTY_ONLY" == "true" ]] && echo "first-party only" || echo "full (first-party + vendor)" )"
    echo ""
  } >> "$SUMMARY"

  [[ "$JSON_OUTPUT" == "true" ]] && echo '[' > "$JSON_FILE"

  declare -A TOTAL_BY_CLASS=( [CRITICAL]=0 [WARNING]=0 [AUDIT]=0 [INFO]=0 [XCRYPTO]=0 )
  local first_json=true

  for repo_dir in "$REPOS_DIR"/*/; do
    [[ -d "$repo_dir" ]] || continue
    local repo_name
    repo_name=$(basename "$repo_dir")

    [[ -n "$COMPONENT" && "$repo_name" != "$COMPONENT" ]] && continue

    local repo_detail="$OUTPUT_DIR/${repo_name}-$TIMESTAMP.txt"
    : > "$repo_detail"

    echo "" >> "$SUMMARY"
    header "Component: $repo_name" "$SUMMARY"

    declare -A repo_counts=( [CRITICAL]=0 [WARNING]=0 [AUDIT]=0 [INFO]=0 [XCRYPTO]=0 )
    declare -A repo_pkg_counts=()

    echo "  Scanning $repo_name..." >&2

    scan_crypto_imports "$repo_dir" "$repo_detail" repo_counts repo_pkg_counts
    scan_xcrypto "$repo_dir" "$repo_detail" repo_counts
    scan_small_rsa_keys "$repo_dir" "$repo_detail" repo_counts
    scan_math_rand_mixing "$repo_dir" "$repo_detail"

    local fp_crit=0 fp_warn=0 fp_audit=0
    compute_fp_split "$repo_dir" fp_crit fp_warn fp_audit

    {
      echo ""
      echo "  CRITICAL : ${repo_counts[CRITICAL]} findings (first-party: $fp_crit)"
      echo "  WARNING  : ${repo_counts[WARNING]} findings (first-party: $fp_warn)"
      echo "  AUDIT    : ${repo_counts[AUDIT]} findings (first-party: $fp_audit)"
      echo "  INFO     : ${repo_counts[INFO]} findings"
      echo "  XCRYPTO  : ${repo_counts[XCRYPTO]} findings"
      echo ""
    } >> "$SUMMARY"

    if [[ ${#repo_pkg_counts[@]} -gt 0 ]]; then
      echo "  Top crypto/ packages:" >> "$SUMMARY"
      for pkg in $(for k in "${!repo_pkg_counts[@]}"; do echo "$k ${repo_pkg_counts[$k]}"; done | sort -k2 -rn | head -10 | awk '{print $1}'); do
        local count="${repo_pkg_counts[$pkg]}"
        local class="${CRYPTO_CLASS[$pkg]}"
        echo "    ${pkg} — ${count} files [$class]" >> "$SUMMARY"
      done
    fi

    echo "  Detail: $repo_detail" >> "$SUMMARY"

    if [[ "$JSON_OUTPUT" == "true" ]]; then
      [[ "$first_json" == "true" ]] && first_json=false || echo ',' >> "$JSON_FILE"
      emit_json_component "$repo_name" repo_counts "$fp_crit" "$fp_warn" "$fp_audit" >> "$JSON_FILE"
    fi

    for cls in CRITICAL WARNING AUDIT INFO XCRYPTO; do
      TOTAL_BY_CLASS[$cls]=$(( ${TOTAL_BY_CLASS[$cls]} + ${repo_counts[$cls]} ))
    done

    unset repo_counts repo_pkg_counts
    declare -A repo_counts repo_pkg_counts
  done

  # Grand summary
  {
    echo ""
    echo "============================================================"
    echo "GRAND TOTAL"
    echo "============================================================"
    echo ""
    echo "  CRITICAL : ${TOTAL_BY_CLASS[CRITICAL]} findings"
    echo "  WARNING  : ${TOTAL_BY_CLASS[WARNING]} findings"
    echo "  AUDIT    : ${TOTAL_BY_CLASS[AUDIT]} findings"
    echo "  INFO     : ${TOTAL_BY_CLASS[INFO]} findings"
    echo "  XCRYPTO  : ${TOTAL_BY_CLASS[XCRYPTO]} findings"
    echo ""
    local total_actionable=$(( ${TOTAL_BY_CLASS[CRITICAL]} + ${TOTAL_BY_CLASS[WARNING]} + ${TOTAL_BY_CLASS[AUDIT]} ))
    echo "  Total actionable (CRITICAL + WARNING + AUDIT): $total_actionable"
    echo ""
  } >> "$SUMMARY"

  [[ "$VENDOR_SUMMARY" == "true" ]] && generate_vendor_summary "$SUMMARY"

  if [[ "$JSON_OUTPUT" == "true" ]]; then
    echo '' >> "$JSON_FILE"
    echo ']' >> "$JSON_FILE"
    echo "    JSON: $JSON_FILE" >&2
  fi

  echo "" >&2
  echo "==> Audit complete." >&2
  echo "    Summary: $SUMMARY" >&2
  echo "    Results: $OUTPUT_DIR/" >&2
  echo "" >&2
  cat "$SUMMARY"
}

main "$@"
