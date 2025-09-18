#!/usr/bin/env bash
# tls_audit2.sh — Defensive TLS/SSL auditing script (testssl.sh removed)
# Usage: ./tls_audit2.sh domain[:port] [domain2[:port] ...]
# Example: ./tls_audit2.sh example.com example.net:8443 mail.example.com:25
#
# Produces: ./tls_audit_reports/<timestamp>/* with outputs and summary
#
# WARNING: Run only on systems you own or have written authorization to test.
# defensive checks only. (uses sslyze/sslscan/nmap/openssl/curl)

set -u
IFS=$'\n\t'

# -------------------------
# Helpers & env
# -------------------------
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTDIR="tls_audit_reports/${TIMESTAMP}"
mkdir -p "$OUTDIR"

# Tools we prefer (not all required; script falls back gracefully)
REQ_TOOLS=(openssl curl nmap)
OPTIONAL_TOOLS=(sslyze sslscan masscan)

# Check and locate tools
declare -A TOOLPATH
echo "🔎 Checking required tools..."
for t in "${REQ_TOOLS[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then
    TOOLPATH[$t]="$(command -v $t)"
    echo "  ✅ Found $t -> ${TOOLPATH[$t]}"
  else
    echo "  ❌ Missing required tool: $t. Please install it and re-run."
  fi
done

for t in "${OPTIONAL_TOOLS[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then
    TOOLPATH[$t]="$(command -v $t)"
    echo "  ✅ Optional tool $t -> ${TOOLPATH[$t]}"
  else
    echo "  ⚠️ Optional tool not found: $t (some checks will be skipped)."
  fi
done

# -------------------------
# Utility functions
# -------------------------
log() { printf '%s\n' "$*" | tee -a "$OUTDIR/summary.txt"; }
sep() { echo "------------------------------------------------------------" | tee -a "$OUTDIR/summary.txt"; }

# Normalize host:port input; default port 443
normalize() {
  local arg="$1"
  if [[ "$arg" == *:* ]]; then
    printf '%s\n' "$arg"
  else
    printf '%s:443\n' "$arg"
  fi
}

# -------------------------
# Core check functions
# -------------------------
check_openssl_versions() {
  log "🔐 OpenSSL version (local):"
  if command -v openssl >/dev/null 2>&1; then
    openssl version -a 2>/dev/null | tee -a "$OUTDIR/openssl_version.txt"
  else
    log "  ❌ openssl not found on PATH"
  fi
  sep
}

probe_with_openssl() {
  local hostport="$1"
  local host="${hostport%%:*}"
  local port="${hostport##*:}"
  local basefn="$OUTDIR/openssl_${host}_${port}"
  log "🔎 [openssl] Probing $host:$port (TLS versions) — output -> ${basefn}.txt"

  # Try TLSv1, TLSv1_1, TLSv1_2, TLSv1_3 (where supported by local openssl)
  for flag in "-ssl2" "-ssl3" "-tls1" "-tls1_1" "-tls1_2" "-tls1_3"; do
    {
      printf '\n=== Attempt %s ===\n' "$flag"
      timeout 10 openssl s_client -connect "${host}:${port}" ${flag} -servername "${host}" < /dev/null 2>&1
    } >>"${basefn}.txt" || true
  done

  {
    printf '\n\n=== Certificate chain and details ===\n'
    timeout 10 openssl s_client -connect "${host}:${port}" -servername "${host}" -showcerts < /dev/null 2>/dev/null \
      | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > "${basefn}_chain.pem" || true
    if [[ -s "${basefn}_chain.pem" ]]; then
      openssl x509 -in "${basefn}_chain.pem" -noout -text >>"${basefn}.txt" 2>&1 || true
    else
      echo "No cert chain retrieved." >>"${basefn}.txt"
    fi
  } >>"${basefn}.txt" 2>&1

  if [[ -s "${basefn}_chain.pem" ]]; then
    cert="${basefn}_chain.pem"
    exp="$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | sed 's/notAfter=//')"
    subj="$(openssl x509 -in "$cert" -noout -subject 2>/dev/null)"
    san="$(openssl x509 -in "$cert" -text 2>/dev/null | awk '/X509v3 Subject Alternative Name/{getline; print; exit}')"
    keybits="$(openssl x509 -in "$cert" -text 2>/dev/null | awk '/Public-Key: \([0-9]+ bit/{print; exit}')"
    printf 'Certificate summary for %s:%s\n  Subject: %s\n  SAN: %s\n  Expires: %s\n  Key info: %s\n' "$host" "$port" "$subj" "$san" "$exp" "$keybits" \
      | tee -a "$OUTDIR/summary.txt"
  else
    log "  ⚠️ Could not retrieve certificate chain via openssl for $host:$port"
  fi
  sep
}

nmap_tls_enum() {
  local hostport="$1"
  local host="${hostport%%:*}"
  local port="${hostport##*:}"
  if ! command -v nmap >/dev/null 2>&1; then
    log "  ⚠️ Skipping nmap scan (nmap not installed)."
    return
  fi
  log "🧭 Running nmap ssl-enum-ciphers on ${host}:${port} (output -> nmap_${host}_${port}.txt)"
  nmap --script ssl-enum-ciphers -p "${port}" "${host}" -oN "${OUTDIR}/nmap_${host}_${port}.txt" 2>/dev/null || true
  sep
}

run_sslyze() {
  local hostport="$1"
  if command -v sslyze >/dev/null 2>&1; then
    log "🐍 Running sslyze (scan all) for $hostport -> sslyze_${hostport//[:\/]/_}.txt"
    # Use --regular + assess for heartbleed/drown/logjam-like checks where possible
    sslyze --regular "$hostport" 2>&1 | tee "${OUTDIR}/sslyze_${hostport//[:\/]/_}.txt" || true
    sep
  else
    log "  ⚠️ sslyze not installed — skipping (recommended replacement for testssl.sh)."
  fi
}

run_sslscan() {
  local hostport="$1"
  if command -v sslscan >/dev/null 2>&1; then
    log "⚡ Running sslscan for $hostport -> sslscan_${hostport//[:\/]/_}.txt"
    sslscan "$hostport" 2>&1 | tee "${OUTDIR}/sslscan_${hostport//[:\/]/_}.txt" || true
    sep
  else
    log "  ⚠️ sslscan not installed — skipping (optional)."
  fi
}

check_dhparams() {
  local hostport="$1"
  local host="${hostport%%:*}"
  local port="${hostport##*:}"
  log "🔐 Checking DH params via openssl for $host:$port"
  openssl s_client -connect "${host}:${port}" -servername "${host}" < /dev/null 2>/dev/null |& tee "${OUTDIR}/openssl_dh_${host}_${port}.txt" || true
  awk '/Server Temp Key/ || /DH Parameters/ || /DH Prime/' "${OUTDIR}/openssl_dh_${host}_${port}.txt" | tee -a "${OUTDIR}/summary.txt" || true
  sep
}

check_hsts_and_mixed() {
  local host="$1"
  local port="$2"
  log "🌐 Checking HSTS header and mixed-content for $host:$port"
  hdrfile="${OUTDIR}/curl_hdr_${host}_${port}.txt"
  bodyfile="${OUTDIR}/curl_body_${host}_${port}.html"
  if command -v curl >/dev/null 2>&1; then
    curl -Is --max-time 10 --connect-timeout 6 "https://${host}:${port}" -H "Host: ${host}" > "${hdrfile}" 2>/dev/null || true
    curl -s --max-time 10 --connect-timeout 6 "https://${host}:${port}" -H "Host: ${host}" -o "${bodyfile}" 2>/dev/null || true

    grep -i '^strict-transport-security:' "${hdrfile}" | tee -a "${OUTDIR}/summary.txt" || echo "  ❌ No HSTS header found" | tee -a "${OUTDIR}/summary.txt"
    if [[ -s "${bodyfile}" ]]; then
      if grep -i -Eo 'http://[^"'"'" >]+' "${bodyfile}" | head -n 20 > "${OUTDIR}/mixed_${host}_${port}.txt"; then
        log "  ⚠️ Mixed-content (first matches) -> ${OUTDIR}/mixed_${host}_${port}.txt"
      else
        log "  ✅ No obvious http:// mixed-content found in main HTML (naive scan)."
      fi
    else
      log "  ⚠️ Empty body retrieved; unable to check mixed-content."
    fi
  else
    log "  ⚠️ curl not installed — cannot check HSTS / mixed-content"
  fi
  sep
}

check_starttls_smtp() {
  local smtp_host="$1"
  local smtp_port="${2:-25}"
  log "✉️ Checking STARTTLS on ${smtp_host}:${smtp_port}"
  if command -v openssl >/dev/null 2>&1; then
    echo | timeout 10 openssl s_client -starttls smtp -crlf -connect "${smtp_host}:${smtp_port}" -servername "${smtp_host}" 2>&1 | tee "${OUTDIR}/starttls_${smtp_host}_${smtp_port}.txt" || true
    if grep -i -q "STARTTLS" "${OUTDIR}/starttls_${smtp_host}_${smtp_port}.txt"; then
      log "  ✅ STARTTLS appears to be offered (check cert details in the saved output)."
    else
      log "  ℹ️ STARTTLS may not be offered (or openssl probe timed out). Inspect ${OUTDIR}/starttls_${smtp_host}_${smtp_port}.txt"
    fi
  else
    log "  ❌ openssl not available — cannot test STARTTLS"
  fi
  sep
}

# -------------------------
# Main
# -------------------------
if [ "$#" -lt 1 ]; then
  echo "Usage: $0 domain[:port] [domain2[:port] ...]"
  exit 1
fi

log "🔔 TLS/SSL Audit report — generated at ${TIMESTAMP} (UTC)"
sep
check_openssl_versions

for target in "$@"; do
  hostport="$(normalize "$target")"
  host="${hostport%%:*}"
  port="${hostport##*:}"
  log "📌 Starting checks for ${host}:${port}"
  probe_with_openssl "$hostport"
  nmap_tls_enum "$hostport"
  run_sslscan "$hostport"
  run_sslyze "$hostport"
  check_dhparams "$hostport"
  check_hsts_and_mixed "$host" "$port"

  if [[ "$port" -eq 25 || "$port" -eq 587 || "$port" -eq 465 ]]; then
    check_starttls_smtp "$host" "$port"
  else
    if [[ "$port" -eq 443 ]]; then
      mx="$(dig +short MX "$host" 2>/dev/null | sort -n | head -n1 | awk '{print $2}')"
      if [[ -n "$mx" ]]; then
        log "✉️ Found MX ${mx} for ${host} — probing STARTTLS on default port 25"
        check_starttls_smtp "$mx" 25
      fi
    fi
  fi

  sep
done

# -------------------------
# Final summary heuristics (simple)
# -------------------------
log "📋 Quick heuristics summary:"
grep -i -E "SSLv|TLSv|offered|accepted|RC4|EXPORT|NULL|weak|expired|Not After|strict-transport-security|STARTTLS|Server Temp Key|DH Parameters|Heartbleed|DROWN|Logjam|CRIME|BREACH" -I -r "$OUTDIR" 2>/dev/null | sed 's/^/  /' | tee -a "$OUTDIR/summary.txt" || true
sep
cat <<'EOF' >>"$OUTDIR/summary.txt"

🚨 IMPORTANT:
 - This script is for defensive auditing only.
 - It attempts many non-invasive probes (openssl/nmap/sslyze/sslscan). Some organizations may still detect scanning as suspicious.
 - Do NOT run against systems you do not own or have written permission to test.

✅ Suggested next steps (remediation):
 - Disable SSLv2/SSLv3 and TLS1.0/1.1 on servers (configure TLS 1.2+ / TLS 1.3).
 - Remove RC4/EXPORT/NULL ciphers; prefer ECDHE + AES-GCM/CHACHA20-POLY1305.
 - Ensure certificates include full chain, correct SANs, and rotate before expiry (>=2048-bit RSA or ECDSA).
 - Generate strong DH params (2048+), prefer ECDHE to avoid Logjam.
 - Enable OCSP stapling, HSTS (careful with preload), and CSP to prevent mixed content.
 - Patch OpenSSL/LibreSSL/GnuTLS, and server packages urgently when CVEs appear.
 - Add these scans to CI and schedule weekly inventory scans; integrate failures into your ticketing system.

Report directory: ${OUTDIR}
EOF

log "✅ Done. Report directory: ${OUTDIR}"
echo ""
echo "Tip: open '${OUTDIR}/summary.txt' for a human-readable summary. Raw outputs found under ${OUTDIR}/*"
