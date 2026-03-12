#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYSTEMD_DIR="${ROOT_DIR}/systemd"
TARGET_DIR="/etc/systemd/system"

render_unit() {
  local template_path="$1"
  local output_name
  output_name="$(basename "${template_path%.tpl}")"
  sed "s|__DEFENDOS_ROOT__|${ROOT_DIR}|g" "${template_path}" | sudo tee "${TARGET_DIR}/${output_name}" >/dev/null
}

for template in \
  "${SYSTEMD_DIR}/defendos-healthcheck.service.tpl" \
  "${SYSTEMD_DIR}/defendos-mailbox-poller.service.tpl" \
  "${SYSTEMD_DIR}/defendos-dashboard.service.tpl"
do
  render_unit "${template}"
done

sudo install -m 0644 \
  "${SYSTEMD_DIR}/defendos-healthcheck.timer" \
  "${SYSTEMD_DIR}/defendos-mailbox-poller.timer" \
  -t "${TARGET_DIR}/"

sudo systemctl daemon-reload
sudo systemctl enable --now defendos-healthcheck.timer defendos-mailbox-poller.timer defendos-dashboard.service
