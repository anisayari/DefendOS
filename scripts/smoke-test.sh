#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON:-python3}"

bash -n "${ROOT_DIR}/healthcheck.sh"
"${PYTHON_BIN}" -m py_compile "${ROOT_DIR}/defendos.py" "${ROOT_DIR}/runtime_inventory.py"

if command -v node >/dev/null 2>&1; then
  js_check_file="$(mktemp --suffix=.js)"
  trap 'rm -f "${js_check_file}"' EXIT
  awk '/<script>/{flag=1;next}/<\/script>/{flag=0}flag' "${ROOT_DIR}/dashboard.html" > "${js_check_file}"
  node --check "${js_check_file}"
fi

healthcheck_exit=0
if ! "${PYTHON_BIN}" "${ROOT_DIR}/defendos.py" healthcheck --skip-codex --no-email; then
  healthcheck_exit=$?
fi

if [[ "${healthcheck_exit}" -ne 0 && "${healthcheck_exit}" -ne 2 ]]; then
  exit "${healthcheck_exit}"
fi

"${PYTHON_BIN}" "${ROOT_DIR}/defendos.py" poll-inbox --skip-codex
