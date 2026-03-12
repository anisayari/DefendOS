#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON:-python3}"

"${PYTHON_BIN}" -m py_compile "${ROOT_DIR}/defendos.py"

healthcheck_exit=0
if ! "${PYTHON_BIN}" "${ROOT_DIR}/defendos.py" healthcheck --skip-codex --no-email; then
  healthcheck_exit=$?
fi

if [[ "${healthcheck_exit}" -ne 0 && "${healthcheck_exit}" -ne 2 ]]; then
  exit "${healthcheck_exit}"
fi

"${PYTHON_BIN}" "${ROOT_DIR}/defendos.py" poll-inbox --skip-codex
