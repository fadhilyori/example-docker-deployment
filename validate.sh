#!/bin/bash

# -----------------------------------------------------------------------------
# Certificate Validation Script
# -----------------------------------------------------------------------------

set -euo pipefail

# Global variables
QUIET_MODE=false
FULL_MODE=false
ALL_MODE=false
CERT_DIR="./ssl_certs"
CERT_FILE=""

# --- Utility Functions ---

# Error exit function
error_exit() {
    echo "Error: $1" >&2
    exit 1
}

# Show help message
show_help() {
    cat << EOF
Usage: ./validate.sh [OPTIONS] <certificate_file>
   or: ./validate.sh [OPTIONS] --all

Validate and display details of a Certificate Authority (CA) certificate.

Options:
  -h, --help              Show this help message
  -f, --full              Show full certificate details
  -q, --quiet             Only show validation result (pass/fail)
  -a, --all               Validate all certificates in the directory
  -d, --dir DIR           Specify certificate directory (default: ./ssl_certs)

Arguments:
  certificate_file        Path to the certificate file to validate

Examples:
  ./validate.sh ssl_certs/MyCA.crt             # Validate and show summary
  ./validate.sh --full ssl_certs/MyCA.crt      # Show full certificate details
  ./validate.sh --quiet ssl_certs/MyCA.crt     # Quick pass/fail check
  ./validate.sh --all                          # Validate all certs in ssl_certs/
  ./validate.sh --all --dir ./ssl_certs        # Explicit dir
  ./validate.sh --all --quiet                  # Quick pass/fail for all
  ./validate.sh --all --full                   # Show details for all certs

EOF
}

# --- Validation Functions ---

# Check if certificate is a valid CA certificate
is_ca_certificate() {
    local cert_file="$1"
    
    # Check if basicConstraints extension exists and has CA:TRUE
    local ca_check
    ca_check=$(openssl x509 -in "$cert_file" -noout -text | grep -A1 "Basic Constraints" || true)
    
    if [[ "$ca_check" =~ "CA:TRUE" ]]; then
        return 0
    else
        return 1
    fi
}

# Check if certificate has required keyUsage for CA
has_ca_key_usage() {
    local cert_file="$1"
    
    # Check if keyUsage includes Certificate Sign
    local key_usage
    key_usage=$(openssl x509 -in "$cert_file" -noout -text | grep -A1 "X509v3 Key Usage" || true)
    
    if [[ "$key_usage" =~ "Certificate Sign" ]]; then
        return 0
    else
        return 1
    fi
}

# Get certificate subject
get_certificate_subject() {
    local cert_file="$1"
    openssl x509 -in "$cert_file" -noout -subject | sed 's/subject=//'
}

# Get certificate issuer
get_certificate_issuer() {
    local cert_file="$1"
    openssl x509 -in "$cert_file" -noout -issuer | sed 's/issuer=//'
}

# Get certificate validity period
get_certificate_validity() {
    local cert_file="$1"
    local not_before
    local not_after
    
    not_before=$(openssl x509 -in "$cert_file" -noout -startdate | sed 's/notBefore=//')
    not_after=$(openssl x509 -in "$cert_file" -noout -enddate | sed 's/notAfter=//')
    
    echo "From: $not_before"
    echo "To:   $not_after"
}

# Get certificate key size
get_certificate_key_size() {
    local cert_file="$1"
    openssl x509 -in "$cert_file" -noout -text | grep "Public-Key:" | sed 's/.*(\([0-9]*\) bit).*/\1/' || echo "Unknown"
}

# Get certificate signature algorithm
get_certificate_signature_algorithm() {
    local cert_file="$1"
    openssl x509 -in "$cert_file" -noout -text | grep "Signature Algorithm" | head -1 | sed 's/.*Signature Algorithm: //' || echo "Unknown"
}

# Get certificate fingerprints
get_certificate_fingerprints() {
    local cert_file="$1"
    
    echo "SHA-256: $(openssl x509 -in "$cert_file" -noout -fingerprint -sha256 | sed 's/SHA256 Fingerprint=//')"
    echo "SHA-1:   $(openssl x509 -in "$cert_file" -noout -fingerprint -sha1 | sed 's/SHA1 Fingerprint=//')"
}

# Show full certificate details
show_full_details() {
    local cert_file="$1"
    openssl x509 -in "$cert_file" -text -noout
}

# Get certificate expiry date
get_certificate_expiry() {
    local cert_file="$1"
    openssl x509 -in "$cert_file" -noout -enddate | sed 's/notAfter=//'
}

# Check if certificate is self-signed
is_self_signed() {
    local cert_file="$1"
    local subject
    local issuer
    subject=$(openssl x509 -in "$cert_file" -noout -subject | sed 's/subject=//')
    issuer=$(openssl x509 -in "$cert_file" -noout -issuer | sed 's/issuer=//')
    if [[ "$subject" == "$issuer" ]]; then
        return 0
    else
        return 1
    fi
}

# Validate a single certificate and report results
# Returns 0 for pass, 1 for fail
validate_and_report() {
    local cert_file="$1"
    local is_valid=true
    local is_ca
    local has_key_usage

    # Validate certificate format
    if ! openssl x509 -in "$cert_file" -noout -text >/dev/null 2>&1; then
        if [[ "$QUIET_MODE" == "false" ]]; then
            echo "❌ Invalid certificate format"
        else
            echo "FAIL"
        fi
        return 1
    fi

    # Determine if CA cert
    if is_ca_certificate "$cert_file"; then
        is_ca=true
    else
        is_ca=false
    fi

    if has_ca_key_usage "$cert_file"; then
        has_key_usage=true
    else
        has_key_usage=false
    fi

    if [[ "$is_ca" != "true" || "$has_key_usage" != "true" ]]; then
        is_valid=false
    fi

    if [[ "$QUIET_MODE" == "true" ]]; then
        if [[ "$is_valid" == "true" ]]; then
            echo "PASS"
            return 0
        else
            echo "FAIL"
            return 1
        fi
    fi

    # Non-quiet output
    echo "File: $(realpath "$cert_file")"

    if [[ "$is_valid" == "true" ]]; then
        echo "✅ Result: VALID CA Certificate"
    else
        echo "❌ Result: INVALID CA Certificate"
    fi

    if [[ "$FULL_MODE" == "true" ]]; then
        echo ""
        show_full_details "$cert_file"
    else
        echo "Subject: $(get_certificate_subject "$cert_file")"
        echo "Issuer:  $(get_certificate_issuer "$cert_file")"
        echo "Expiry:  $(get_certificate_expiry "$cert_file")"

        if is_self_signed "$cert_file"; then
            echo "Type:    Self-signed (CA)"
        else
            echo "Type:    Signed by another CA"
        fi
    fi

    echo ""

    if [[ "$is_valid" == "true" ]]; then
        return 0
    else
        return 1
    fi
}

# Validate all certificates in a directory
validate_all_certs() {
    local dir="$1"
    local total=0
    local passed=0
    local failed=0
    local cert_files=()

    if [[ ! -d "$dir" ]]; then
        error_exit "Directory not found: $dir"
    fi

    # Collect all .crt and .pem files (excluding .key files)
    while IFS= read -r -d '' file; do
        cert_files+=("$file")
    done < <(find "$dir" -type f \( -name "*.crt" -o -name "*.pem" \) ! -name "*.key" -print0 2>/dev/null || true)

    if [[ ${#cert_files[@]} -eq 0 ]]; then
        if [[ "$QUIET_MODE" == "false" ]]; then
            echo "No certificate files found in $dir"
        fi
        exit 0
    fi

    # Sort the files for consistent output
    IFS=$'\n' cert_files=($(sort <<<"${cert_files[*]}")); unset IFS

    if [[ "$QUIET_MODE" == "false" ]]; then
        echo "Certificate Validation Report (All Certificates)"
        echo "================================================"
        echo "Directory: $(realpath "$dir")"
        echo "Found: ${#cert_files[@]} certificate file(s)"
        echo ""
    fi

    for cert_file in "${cert_files[@]}"; do
        total=$((total + 1))

        if [[ "$QUIET_MODE" == "false" ]]; then
            echo "--- [$total/${#cert_files[@]}] ---"
        fi

        if validate_and_report "$cert_file"; then
            passed=$((passed + 1))
        else
            failed=$((failed + 1))
        fi
    done

    # Summary
    if [[ "$QUIET_MODE" == "false" ]]; then
        echo "Summary"
        echo "======="
        echo "Total checked: $total"
        echo "Passed:        $passed"
        echo "Failed:        $failed"
    fi

    if [[ $failed -gt 0 ]]; then
        exit 1
    else
        exit 0
    fi
}

# --- Main Script ---

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -f|--full)
                FULL_MODE=true
                shift
                ;;
            -q|--quiet)
                QUIET_MODE=true
                shift
                ;;
            -a|--all)
                ALL_MODE=true
                shift
                ;;
            -d|--dir)
                if [[ -n "${2:-}" && ! "${2:-}" =~ ^- ]]; then
                    CERT_DIR="$2"
                    shift 2
                else
                    error_exit "Directory path required after $1. Use --help for usage information."
                fi
                ;;
            -*)
                error_exit "Unknown option: $1. Use --help for usage information."
                ;;
            *)
                if [[ -z "$CERT_FILE" ]]; then
                    CERT_FILE="$1"
                else
                    error_exit "Multiple certificate files specified. Use --help for usage information."
                fi
                shift
                ;;
        esac
    done

    # Handle --all mode
    if [[ "$ALL_MODE" == "true" ]]; then
        validate_all_certs "$CERT_DIR"
    fi

    # Single certificate mode
    # Check if certificate file is specified
    [[ -n "$CERT_FILE" ]] || error_exit "Certificate file is required. Use --help for usage information."

    # Check if certificate file exists
    [[ -f "$CERT_FILE" ]] || error_exit "Certificate file not found: $CERT_FILE"

    # Validate certificate format
    if ! openssl x509 -in "$CERT_FILE" -noout -text >/dev/null 2>&1; then
        if [[ "$QUIET_MODE" == "false" ]]; then
            echo "❌ Invalid certificate format"
        fi
        exit 1
    fi

    # Perform CA validation
    local is_ca
    local has_key_usage

    if is_ca_certificate "$CERT_FILE"; then
        is_ca=true
    else
        is_ca=false
    fi

    if has_ca_key_usage "$CERT_FILE"; then
        has_key_usage=true
    else
        has_key_usage=false
    fi

    # Determine overall validation result
    local is_valid_ca=false
    if [[ "$is_ca" == "true" && "$has_key_usage" == "true" ]]; then
        is_valid_ca=true
    fi

    # Output results
    if [[ "$QUIET_MODE" == "true" ]]; then
        if [[ "$is_valid_ca" == "true" ]]; then
            echo "PASS"
            exit 0
        else
            echo "FAIL"
            exit 1
        fi
    fi

    # Show summary
    echo "Certificate Validation Report"
    echo "============================"
    echo "File: $(realpath "$CERT_FILE")"
    echo ""

    if [[ "$is_valid_ca" == "true" ]]; then
        echo "✅ Result: VALID CA Certificate"
    else
        echo "❌ Result: INVALID CA Certificate"
    fi
    echo ""

    echo "CA Extensions Check:"
    echo "  Basic Constraints (CA:TRUE): $([[ "$is_ca" == "true" ]] && echo "✅ Present" || echo "❌ Missing")"
    echo "  Key Usage (keyCertSign):    $([[ "$has_key_usage" == "true" ]] && echo "✅ Present" || echo "❌ Missing")"
    echo ""

    if [[ "$FULL_MODE" == "true" ]]; then
        echo "Full Certificate Details:"
        echo "========================="
        show_full_details "$CERT_FILE"
    else
        echo "Certificate Information:"
        echo "-----------------------"
        echo "Subject: $(get_certificate_subject "$CERT_FILE")"
        echo "Issuer:  $(get_certificate_issuer "$CERT_FILE")"
        echo ""
        echo "Validity Period:"
        get_certificate_validity "$CERT_FILE"
        echo ""
        echo "Key Information:"
        echo "  Size: $(get_certificate_key_size "$CERT_FILE") bits"
        echo "  Signature Algorithm: $(get_certificate_signature_algorithm "$CERT_FILE")"
        echo ""
        echo "Fingerprints:"
        get_certificate_fingerprints "$CERT_FILE"
        echo ""
        echo "Use --full to see complete certificate details."
    fi

    # Exit with appropriate code
    if [[ "$is_valid_ca" == "true" ]]; then
        exit 0
    else
        exit 1
    fi
}

# Run main function with all arguments
main "$@"