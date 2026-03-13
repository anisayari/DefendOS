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

perm_allows_group_or_world_write() {
  local mode="${1:-}"
  local group_digit other_digit

  [ -n "$mode" ] || return 1
  group_digit="${mode: -2:1}"
  other_digit="${mode: -1}"

  case "$group_digit" in
    2|3|6|7) return 0 ;;
  esac

  case "$other_digit" in
    2|3|6|7) return 0 ;;
  esac

  return 1
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
      tcp|tcp6|udp|udp6) ;;
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

check_auto_updates() {
  local enabled_status active_status apt_periodic_enabled

  if have dpkg-query; then
    if dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q 'install ok installed'; then
      enabled_status="$(systemctl is-enabled unattended-upgrades.service 2>/dev/null || true)"
      active_status="$(systemctl is-active unattended-upgrades.service 2>/dev/null || true)"
      apt_periodic_enabled="unknown"
      if grep -RhsEq 'APT::Periodic::Unattended-Upgrade[[:space:]]+"1";' /etc/apt/apt.conf.d 2>/dev/null; then
        apt_periodic_enabled="enabled"
      elif grep -RhsEq 'APT::Periodic::Unattended-Upgrade[[:space:]]+"0";' /etc/apt/apt.conf.d 2>/dev/null; then
        apt_periodic_enabled="disabled"
      fi
      printf 'unattended-upgrades enabled: %s\n' "${enabled_status:-unknown}"
      printf 'unattended-upgrades active: %s\n' "${active_status:-unknown}"
      printf 'APT periodic unattended-upgrade: %s\n' "${apt_periodic_enabled:-unknown}"
      if [ "$apt_periodic_enabled" = "enabled" ] || [ "$enabled_status" = "enabled" ]; then
        ok "Automatic security upgrades are enabled"
      else
        warn "Automatic security upgrades are not enabled"
      fi
      return
    fi

    warn "Automatic security upgrades are not installed"
    return
  fi

  if have rpm && rpm -q dnf-automatic >/dev/null 2>&1; then
    enabled_status="$(systemctl is-enabled dnf-automatic.timer 2>/dev/null || true)"
    active_status="$(systemctl is-active dnf-automatic.timer 2>/dev/null || true)"
    printf 'dnf-automatic.timer enabled: %s\n' "${enabled_status:-unknown}"
    printf 'dnf-automatic.timer active: %s\n' "${active_status:-unknown}"
    if [ "$enabled_status" = "enabled" ]; then
      ok "Automatic security upgrades are enabled"
    else
      warn "Automatic security upgrades are not enabled"
    fi
    return
  fi

  warn "Automatic security upgrade status could not be determined on this host"
}

check_tmp_permissions() {
  local tmp_path mode_text world_writable sticky_present

  for tmp_path in /tmp /var/tmp; do
    if [ ! -d "$tmp_path" ]; then
      warn "${tmp_path} does not exist"
      continue
    fi

    mode_text="$(stat -c '%A (%a)' "$tmp_path" 2>/dev/null || true)"
    printf '%s permissions: %s\n' "$tmp_path" "${mode_text:-unavailable}"

    world_writable="$(find "$tmp_path" -maxdepth 0 -perm -0002 -print -quit 2>/dev/null || true)"
    sticky_present="$(find "$tmp_path" -maxdepth 0 -perm -1000 -print -quit 2>/dev/null || true)"

    if [ -n "$world_writable" ] && [ -z "$sticky_present" ]; then
      alert "${tmp_path} is world-writable without the sticky bit"
    elif [ -n "$world_writable" ]; then
      ok "${tmp_path} has the sticky bit set"
    else
      warn "${tmp_path} is not world-writable"
    fi
  done
}

check_mac_framework() {
  local found_framework=0 apparmor_mode selinux_mode

  if [ -r /sys/module/apparmor/parameters/enabled ]; then
    found_framework=1
    apparmor_mode="$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || true)"
    printf 'AppArmor kernel flag: %s\n' "${apparmor_mode:-unknown}"
    if [ "$apparmor_mode" = "Y" ]; then
      ok "AppArmor is enabled"
    else
      warn "AppArmor is not enabled"
    fi
  elif have aa-status; then
    found_framework=1
    if aa-status --enabled >/dev/null 2>&1; then
      ok "AppArmor is enabled"
    else
      warn "AppArmor is installed but not enabled"
    fi
    aa-status 2>/dev/null | head -n 12 || true
  fi

  if have getenforce; then
    found_framework=1
    selinux_mode="$(getenforce 2>/dev/null || true)"
    printf 'SELinux mode: %s\n' "${selinux_mode:-unknown}"
    case "$selinux_mode" in
      Enforcing)
        ok "SELinux is enforcing"
        ;;
      Permissive)
        warn "SELinux is permissive"
        ;;
      Disabled)
        warn "SELinux is disabled"
        ;;
    esac
  fi

  if [ "$found_framework" -eq 0 ]; then
    warn "No mandatory access control framework status was detected"
  fi
}

check_ssh_config() {
  local permit_root password_auth pubkey_auth kbd_auth permit_empty max_auth_tries

  if ! have sshd; then
    warn "sshd binary not found; skipping SSH config checks"
    return
  fi

  permit_root="$(sshd -T 2>/dev/null | awk '/^permitrootlogin / {print $2}')"
  password_auth="$(sshd -T 2>/dev/null | awk '/^passwordauthentication / {print $2}')"
  pubkey_auth="$(sshd -T 2>/dev/null | awk '/^pubkeyauthentication / {print $2}')"
  kbd_auth="$(sshd -T 2>/dev/null | awk '/^kbdinteractiveauthentication / {print $2}')"
  permit_empty="$(sshd -T 2>/dev/null | awk '/^permitemptypasswords / {print $2}')"
  max_auth_tries="$(sshd -T 2>/dev/null | awk '/^maxauthtries / {print $2}')"

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

  if [ "$permit_empty" = "yes" ]; then
    alert "SSH empty passwords are enabled"
  fi

  if [ -n "$max_auth_tries" ] && [ "$max_auth_tries" -gt 4 ] 2>/dev/null; then
    warn "SSH MaxAuthTries is set higher than 4 (${max_auth_tries})"
  fi
}

check_root_ssh_access() {
  local root_ssh auth_keys mode key_count

  root_ssh="/root/.ssh"
  auth_keys="${root_ssh}/authorized_keys"

  if [ ! -d "$root_ssh" ]; then
    warn "Root .ssh directory does not exist"
    return
  fi

  mode="$(stat -c '%a' "$root_ssh" 2>/dev/null || true)"
  printf 'Root .ssh mode: %s\n' "${mode:-unavailable}"
  if perm_allows_group_or_world_write "$mode"; then
    alert "Root SSH directory permissions are too open"
  else
    ok "Root SSH directory permissions look restricted"
  fi

  if [ ! -f "$auth_keys" ]; then
    warn "Root authorized_keys file does not exist"
    return
  fi

  mode="$(stat -c '%a' "$auth_keys" 2>/dev/null || true)"
  key_count="$(grep -Ec '^[[:space:]]*ssh-|^[[:space:]]*ecdsa-|^[[:space:]]*sk-' "$auth_keys" 2>/dev/null || true)"
  printf 'Root authorized_keys mode: %s\n' "${mode:-unavailable}"
  printf 'Root authorized_keys entries: %s\n' "${key_count:-0}"

  if perm_allows_group_or_world_write "$mode"; then
    alert "Root authorized_keys permissions are too open"
  else
    ok "Root authorized_keys permissions look restricted"
  fi

  if find "$auth_keys" -mtime -7 -print -quit 2>/dev/null | grep -q .; then
    warn "Root authorized_keys was modified in the last 7 days"
  fi
}

check_firewall() {
  local status_text verbose_text

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

  verbose_text="$(ufw status verbose 2>&1 || true)"
  if printf '%s\n' "$verbose_text" | grep -q '^Default: '; then
    printf '%s\n' "$verbose_text"
    if ! printf '%s\n' "$verbose_text" | grep -q 'Default: deny (incoming)'; then
      alert "UFW default incoming policy is not deny"
    fi
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
  else
    warn "fail2ban sshd jail is not configured"
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

check_sudo_policy() {
  local matches

  matches="$(grep -RnsE 'NOPASSWD:|!authenticate' /etc/sudoers /etc/sudoers.d 2>/dev/null || true)"
  if [ -n "$matches" ]; then
    warn "Passwordless sudo rules were found"
    printf '%s\n' "$matches" | head -n 20
  else
    ok "No passwordless sudo rule was found in sudoers"
  fi
}

check_cron() {
  printf 'Root crontab:\n'
  crontab -l 2>/dev/null || printf 'none\n'

  printf '\nSystem cron files:\n'
  find /etc/cron* -maxdepth 2 -type f 2>/dev/null | sort
}

check_shell_persistence() {
  local path changed_paths=""

  for path in /etc/profile /etc/bash.bashrc /etc/profile.d /etc/zsh/zshrc /etc/zsh/zprofile /etc/rc.local /root/.bashrc /root/.bash_profile /root/.profile /root/.zshrc; do
    if [ -d "$path" ]; then
      changed_paths="$(
        printf '%s\n%s' "$changed_paths" "$(find "$path" -maxdepth 1 -type f -mtime -7 2>/dev/null | sort)"
      )"
    elif [ -f "$path" ]; then
      changed_paths="$(
        printf '%s\n%s' "$changed_paths" "$(find "$path" -maxdepth 0 -type f -mtime -7 2>/dev/null | sort)"
      )"
    fi
  done

  changed_paths="$(printf '%s\n' "$changed_paths" | sed '/^$/d' | sort -u | head -n 40)"
  if [ -n "$changed_paths" ]; then
    warn "Shell startup files changed in the last 7 days"
    printf '%s\n' "$changed_paths"
  else
    ok "No recent shell startup file change detected"
  fi
}

check_persistence_changes() {
  local changed_paths

  changed_paths="$(
    find /etc/systemd/system /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly /var/spool/cron /root/.ssh \
      -xdev -type f -mtime -7 2>/dev/null | sort | head -n 40
  )"

  if [ -n "$changed_paths" ]; then
    warn "Sensitive persistence files changed in the last 7 days"
    printf '%s\n' "$changed_paths"
  else
    ok "No recent persistence file change detected in the watched paths"
  fi
}

check_sensitive_permissions() {
  local world_writable_files

  world_writable_files="$(
    find /etc /root /usr/local/bin /usr/local/sbin -xdev -type f -perm -0002 2>/dev/null | sort | head -n 40
  )"

  if [ -n "$world_writable_files" ]; then
    alert "Sensitive paths contain world-writable files"
    printf '%s\n' "$world_writable_files"
  else
    ok "No world-writable file found in sensitive paths"
  fi
}

check_suid_sgid() {
  local flagged_files

  flagged_files="$(
    find /tmp /var/tmp /home /usr/local/bin /usr/local/sbin -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort | head -n 40
  )"

  if [ -n "$flagged_files" ]; then
    warn "SUID or SGID files were found in local or writable paths"
    printf '%s\n' "$flagged_files"
  else
    ok "No SUID or SGID file found in local or writable paths"
  fi
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
  check_auto_updates
  check_reboot_required
  check_tmp_permissions
  check_mac_framework

  section "SSH and Auth"
  check_ssh_config
  check_root_ssh_access
  check_recent_auth_activity
  check_current_sessions

  section "Network Exposure"
  check_firewall
  check_fail2ban
  check_public_ports

  section "Accounts and Persistence"
  check_privileged_accounts
  check_sudo_policy
  check_cron
  check_shell_persistence
  check_persistence_changes
  check_sensitive_permissions
  check_suid_sgid

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
