#!/usr/bin/env bash

set -u

EXPECTED_PUBLIC_PORTS_DEFAULT="22 80 443"
EXPECTED_PUBLIC_PORTS="${EXPECTED_PUBLIC_PORTS:-$EXPECTED_PUBLIC_PORTS_DEFAULT}"
AUTH_LOG="${AUTH_LOG:-/var/log/auth.log}"
MAX_AUTH_LINES="${MAX_AUTH_LINES:-4000}"

alerts=0
warnings=0

section() {
  printf '\n== %s ==\n' "$1"
}

ok() {
  printf '[OK] %s\n' "$1"
}

warn() {
  warnings=$((warnings + 1))
  printf '[WARN] %s\n' "$1"
}

alert() {
  alerts=$((alerts + 1))
  printf '[ALERT] %s\n' "$1"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

print_cmd_output() {
  local label="$1"
  shift

  printf '%s\n' "$label"
  if "$@" 2>/dev/null; then
    :
  else
    printf 'unavailable\n'
  fi
}

listening_ports() {
  ss -lntuH 2>/dev/null | while read -r proto state recvq sendq local_addr peer_addr; do
    case "$proto" in
      tcp|tcp6) ;;
      *) continue ;;
    esac
    port="${local_addr##*:}"
    host="${local_addr%:*}"
    if [ "$host" = "*" ] || [ "$host" = "0.0.0.0" ] || [ "$host" = "[::]" ]; then
      printf '%s\n' "$port"
    fi
  done | sort -n -u
}

port_is_expected() {
  local port="$1"
  local expected

  for expected in $EXPECTED_PUBLIC_PORTS; do
    if [ "$expected" = "$port" ]; then
      return 0
    fi
  done

  return 1
}

check_disk_usage() {
  local flagged=0

  while read -r fs size used avail usep mount; do
    [ -n "${fs:-}" ] || continue
    usep="${usep%%%}"
    if [ "$usep" -ge 90 ]; then
      alert "Disk usage is ${usep}% on ${mount}"
      flagged=1
    elif [ "$usep" -ge 80 ]; then
      warn "Disk usage is ${usep}% on ${mount}"
      flagged=1
    fi
  done < <(df -hP / /var /home 2>/dev/null | tail -n +2)

  if [ "$flagged" -eq 0 ]; then
    ok "Disk usage is below 80% on /, /var and /home"
  fi
}

check_memory() {
  local mem_line mem_total mem_used mem_free mem_shared mem_cache mem_available

  mem_line="$(free -m 2>/dev/null | awk '/^Mem:/ {print $2, $3, $4, $5, $6, $7}')"
  if [ -z "$mem_line" ]; then
    warn "Unable to read memory usage"
    return
  fi

  read -r mem_total mem_used mem_free mem_shared mem_cache mem_available <<<"$mem_line"
  if [ "$mem_total" -gt 0 ]; then
    local used_pct
    used_pct=$((mem_used * 100 / mem_total))
    if [ "$used_pct" -ge 90 ]; then
      alert "Memory usage is ${used_pct}% (${mem_used}MB/${mem_total}MB)"
    elif [ "$used_pct" -ge 80 ]; then
      warn "Memory usage is ${used_pct}% (${mem_used}MB/${mem_total}MB)"
    else
      ok "Memory usage is ${used_pct}% (${mem_used}MB/${mem_total}MB)"
    fi
  fi
}

check_load() {
  local load_1 load_5 load_15 cpu_count

  read -r load_1 load_5 load_15 _ < /proc/loadavg
  cpu_count="$(nproc 2>/dev/null || echo 1)"

  awk -v one_min="$load_1" -v cpus="$cpu_count" 'BEGIN { exit !(one_min > cpus * 2) }'
  if [ $? -eq 0 ]; then
    alert "1-minute load average is ${load_1} on ${cpu_count} CPU(s)"
    return
  fi

  awk -v one_min="$load_1" -v cpus="$cpu_count" 'BEGIN { exit !(one_min > cpus) }'
  if [ $? -eq 0 ]; then
    warn "1-minute load average is ${load_1} on ${cpu_count} CPU(s)"
  else
    ok "Load average is ${load_1}/${load_5}/${load_15} on ${cpu_count} CPU(s)"
  fi
}

check_reboot_required() {
  if [ -f /var/run/reboot-required ]; then
    warn "A reboot is required after package updates"
  else
    ok "No pending reboot requirement"
  fi
}

check_ssh_config() {
  local permit_root password_auth pubkey_auth kbd_auth

  if ! have sshd; then
    warn "sshd binary not found; skipping SSH config checks"
    return
  fi

  permit_root="$(sshd -T 2>/dev/null | awk '/^permitrootlogin / {print $2}')"
  password_auth="$(sshd -T 2>/dev/null | awk '/^passwordauthentication / {print $2}')"
  pubkey_auth="$(sshd -T 2>/dev/null | awk '/^pubkeyauthentication / {print $2}')"
  kbd_auth="$(sshd -T 2>/dev/null | awk '/^kbdinteractiveauthentication / {print $2}')"

  if [ "$permit_root" = "yes" ]; then
    alert "SSH root login is enabled"
  elif [ "$permit_root" = "prohibit-password" ] || [ "$permit_root" = "without-password" ]; then
    warn "SSH root login is limited to keys only"
  else
    ok "SSH root login is disabled"
  fi

  if [ "$password_auth" = "yes" ]; then
    alert "SSH password authentication is enabled"
  else
    ok "SSH password authentication is disabled"
  fi

  if [ "$pubkey_auth" = "yes" ]; then
    ok "SSH public key authentication is enabled"
  else
    alert "SSH public key authentication is disabled"
  fi

  if [ "$kbd_auth" = "yes" ]; then
    warn "SSH keyboard-interactive authentication is enabled"
  fi
}

check_firewall() {
  local status_text

  if ! have ufw; then
    warn "ufw is not installed"
    return
  fi

  status_text="$(ufw status 2>&1 || true)"
  if printf '%s\n' "$status_text" | grep -q '^Status: active'; then
    ok "ufw is active"
  elif printf '%s\n' "$status_text" | grep -q '^Status: inactive'; then
    alert "ufw is not active"
  elif [ -n "$status_text" ]; then
    warn "Unable to determine ufw status cleanly"
  else
    warn "ufw returned no status output"
  fi

  printf '%s\n' "$status_text"
}

check_fail2ban() {
  local status_text sshd_status currently_banned

  if ! have fail2ban-client; then
    warn "fail2ban-client is not installed"
    return
  fi

  status_text="$(fail2ban-client status 2>&1 || true)"
  if printf '%s\n' "$status_text" | grep -q '^Status'; then
    ok "fail2ban is reachable"
    printf '%s\n' "$status_text"
  else
    warn "Unable to determine fail2ban status cleanly"
    [ -n "$status_text" ] && printf '%s\n' "$status_text"
  fi

  sshd_status="$(fail2ban-client status sshd 2>&1 || true)"
  if printf '%s\n' "$sshd_status" | grep -q 'Currently banned:'; then
    printf '%s\n' "$sshd_status"
    currently_banned="$(printf '%s\n' "$sshd_status" | awk -F'\t' '/Currently banned:/ {print $2}' | tr -d ' ')"
    if [ -n "$currently_banned" ] && [ "$currently_banned" -gt 0 ] 2>/dev/null; then
      warn "fail2ban currently bans ${currently_banned} IP(s) on sshd"
    fi
  fi
}

check_public_ports() {
  local port found_unexpected=0

  printf 'Expected public ports: %s\n' "$EXPECTED_PUBLIC_PORTS"
  printf 'Detected public listening ports:\n'
  listening_ports | sed 's/^/- /'

  while read -r port; do
    [ -n "$port" ] || continue
    if ! port_is_expected "$port"; then
      warn "Unexpected public port listening: ${port}"
      found_unexpected=1
    fi
  done < <(listening_ports)

  if [ "$found_unexpected" -eq 0 ]; then
    ok "No unexpected public listening ports detected"
  fi
}

check_recent_auth_activity() {
  local auth_source ssh_failures invalid_users accepted_password accepted_root_password

  if [ -r "$AUTH_LOG" ]; then
    auth_source="$AUTH_LOG"
  else
    warn "Auth log ${AUTH_LOG} is not readable"
    return
  fi

  ssh_failures="$(tail -n "$MAX_AUTH_LINES" "$auth_source" | grep -c 'Failed password' || true)"
  invalid_users="$(tail -n "$MAX_AUTH_LINES" "$auth_source" | grep -c 'Invalid user' || true)"
  accepted_password="$(tail -n "$MAX_AUTH_LINES" "$auth_source" | grep -c 'Accepted password' || true)"
  accepted_root_password="$(tail -n "$MAX_AUTH_LINES" "$auth_source" | grep -c 'Accepted password for root' || true)"

  printf 'Recent auth log source: %s\n' "$auth_source"
  printf 'Failed password entries: %s\n' "$ssh_failures"
  printf 'Invalid user entries: %s\n' "$invalid_users"
  printf 'Accepted password entries: %s\n' "$accepted_password"

  if [ "$ssh_failures" -gt 0 ] || [ "$invalid_users" -gt 0 ]; then
    warn "Recent SSH brute-force activity detected"
    printf 'Top sources for failed SSH attempts:\n'
    tail -n "$MAX_AUTH_LINES" "$auth_source" \
      | grep -E 'Failed password|Invalid user' \
      | awk '{for (i = 1; i <= NF; i++) if ($i == "from") print $(i + 1)}' \
      | sort | uniq -c | sort -nr | head -n 10
  else
    ok "No recent SSH failures found in the sampled auth log"
  fi

  if [ "$accepted_root_password" -gt 0 ]; then
    alert "Root logged in with a password recently"
    printf 'Accepted password for root entries:\n'
    tail -n "$MAX_AUTH_LINES" "$auth_source" | grep 'Accepted password for root' | tail -n 20
  elif [ "$accepted_password" -gt 0 ]; then
    warn "Password-based SSH logins were accepted recently"
    printf 'Accepted password entries:\n'
    tail -n "$MAX_AUTH_LINES" "$auth_source" | grep 'Accepted password' | tail -n 20
  else
    ok "No recent accepted SSH password logins found in the sampled auth log"
  fi
}

check_current_sessions() {
  local current_root_sessions

  printf 'Current sessions:\n'
  who 2>/dev/null || printf 'unavailable\n'

  printf '\nRecent successful logins:\n'
  last -ai | head -n 12 2>/dev/null || printf 'unavailable\n'

  printf '\nRecent failed logins:\n'
  lastb -ai | head -n 12 2>/dev/null || printf 'unavailable\n'

  current_root_sessions="$(who 2>/dev/null | awk '$1 == "root" {count++} END {print count + 0}')"
  if [ "$current_root_sessions" -gt 1 ]; then
    warn "Multiple root sessions are currently open (${current_root_sessions})"
  fi
}

check_privileged_accounts() {
  local uid0_accounts sudo_members shell_users

  printf 'UID 0 accounts:\n'
  uid0_accounts="$(awk -F: '($3 == 0) {print $1}' /etc/passwd)"
  printf '%s\n' "$uid0_accounts"

  if [ "$(printf '%s\n' "$uid0_accounts" | wc -l)" -gt 1 ]; then
    alert "There is more than one UID 0 account"
  else
    ok "Only root has UID 0"
  fi

  printf '\nUsers with an interactive shell:\n'
  shell_users="$(awk -F: '($7 !~ /(nologin|false)$/) {print $1 ":" $7}' /etc/passwd)"
  printf '%s\n' "$shell_users"

  if getent group sudo >/dev/null 2>&1; then
    printf '\nMembers of sudo:\n'
    sudo_members="$(getent group sudo | awk -F: '{print $4}')"
    if [ -n "$sudo_members" ]; then
      printf '%s\n' "$sudo_members" | tr ',' '\n'
    else
      printf 'none\n'
    fi
  fi
}

check_cron() {
  printf 'Root crontab:\n'
  crontab -l 2>/dev/null || printf 'none\n'

  printf '\nSystem cron files:\n'
  find /etc/cron* -maxdepth 2 -type f 2>/dev/null | sort
}

check_processes() {
  printf 'Top CPU processes:\n'
  ps -eo pid,user,pcpu,pmem,comm,args --sort=-pcpu | head -n 12

  printf '\nTop memory processes:\n'
  ps -eo pid,user,pcpu,pmem,comm,args --sort=-pmem | head -n 12
}

check_recent_changes() {
  printf 'Recent files changed in /home and /root within 24h:\n'
  find /home /root -xdev -type f -mtime -1 2>/dev/null | sort | head -n 40
}

main() {
  printf 'DefendOS healthcheck for %s\n' "$(hostname 2>/dev/null || echo unknown-host)"
  printf 'Generated at %s UTC\n' "$(date -u '+%Y-%m-%d %H:%M:%S')"

  section "System"
  print_cmd_output 'OS release:' cat /etc/os-release
  printf '\nKernel: '
  uname -srmo 2>/dev/null || printf 'unavailable\n'
  printf 'Uptime: '
  uptime -p 2>/dev/null || printf 'unavailable\n'
  check_load
  check_memory
  check_disk_usage
  check_reboot_required

  section "SSH and Auth"
  check_ssh_config
  check_recent_auth_activity
  check_current_sessions

  section "Network Exposure"
  check_firewall
  check_fail2ban
  check_public_ports

  section "Accounts and Persistence"
  check_privileged_accounts
  check_cron

  section "Processes and Recent Changes"
  check_processes
  check_recent_changes

  section "Summary"
  printf 'Warnings: %s\n' "$warnings"
  printf 'Alerts: %s\n' "$alerts"

  if [ "$alerts" -gt 0 ]; then
    exit 2
  fi

  if [ "$warnings" -gt 0 ]; then
    exit 1
  fi

  exit 0
}

main "$@"
