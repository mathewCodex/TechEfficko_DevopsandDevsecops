#!/usr/bin/env bash
# ==============================================================================
# Script Name   : auth_report.sh
# Description   : Automated SSH Brute-Force Log Parser & Reporter
# Usage         : ./auth_report.sh --log <file> --top <N> --out <dir>
# Standards     : POSIX Shell Compliance / Defensive Execution
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# DEFAULT CONFIGURATION & VARIABLES
# ------------------------------------------------------------------------------
LOG_FILE="/var/log/auth.log"
TOP_COUNT=5
OUTPUT_DIR="reports"

# ------------------------------------------------------------------------------
# FUNCTIONS
# ------------------------------------------------------------------------------

# Display usage instructions and exit
show_help() {
  cat << EOF
Usage: $(basename "$0") [OPTIONS]

Parses SSH authentication logs to detect failed login attempts and generate an IP threat report.

Options:
  -h, --help             Show this help message and exit.
  -l, --log FILE         Path to authentication log file (Default: /var/log/auth.log).
  -t, --top NUMBER       Number of top offending IP addresses to list (Default: 5).
  -o, --out DIRECTORY    Output directory for report generation (Default: reports).

Example:
  ./$(basename "$0") --log /var/log/auth.log --top 5 --out reports/
EOF
  exit 0
}

# Validate input parameters and dependencies
validate_inputs() {
  # Check if target log file exists and is readable
  if [[ ! -f "${LOG_FILE}" ]]; then
    echo "Error: Log file '${LOG_FILE}' does not exist or is not readable." >&2
    exit 1
  fi

  # Ensure top count is a positive integer
  if ! [[ "${TOP_COUNT}" =~ ^[0-9]+$ ]] || [[ "${TOP_COUNT}" -eq 0 ]]; then
    echo "Error: --top value must be a positive integer. Provided: '${TOP_COUNT}'" >&2
    exit 1
  fi
}

# Process logs and generate timestamped output file
generate_report() {
  local today_date
  today_date=$(date +%F)
  local report_file="${OUTPUT_DIR}/auth-report-${today_date}.log"

  # Ensure output directory exists
  mkdir -p "${OUTPUT_DIR}"

  echo "=== SSH Authentication Failure Threat Report ===" > "${report_file}"
  echo "Generated On : $(date '+%Y-%m-%d %H:%M:%S')" >> "${report_file}"
  echo "Source Log   : ${LOG_FILE}" >> "${report_file}"
  echo "Top Offenders: ${TOP_COUNT}" >> "${report_file}"
  echo "------------------------------------------------" >> "${report_file}"
  echo "COUNT  IP ADDRESS" >> "${report_file}"
  echo "------------------------------------------------" >> "${report_file}"

  # Extract failed passwords, parse IP addresses, sort by frequency, and append top results
  local failed_ips
  failed_ips=$(grep "Failed password" "${LOG_FILE}" 2>/dev/null \
    | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" \
    | sort \
    | uniq -c \
    | sort -rn \
    | head -n "${TOP_COUNT}" || true)

  if [[ -n "${failed_ips}" ]]; then
    echo "${failed_ips}" >> "${report_file}"
  else
    echo "No SSH login failures detected in target log." >> "${report_file}"
  fi

  echo "------------------------------------------------" >> "${report_file}"
  echo "Report saved to: ${report_file}"
}

# ------------------------------------------------------------------------------
# CLI ARGUMENT PARSING
# ------------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      show_help
      ;;
    -l|--log)
      LOG_FILE="$2"
      shift 2
      ;;
    -t|--top)
      TOP_COUNT="$2"
      shift 2
      ;;
    -o|--out)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    *)
      echo "Error: Unknown argument '$1'" >&2
      echo "Use '--help' for execution options." >&2
      exit 1
      ;;
  esac
done


