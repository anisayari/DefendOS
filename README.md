# DefendOS

DefendOS is a standalone surveillance agent for a whole Linux VPS.

It combines:

1. A machine-wide healthcheck.
2. A read-only `codex exec` investigation path.
3. Email alerts for urgent findings.
4. Email-triggered commands from an approved mailbox.
5. A local dashboard on `127.0.0.1:8787`.

## Repository layout

- `defendos.py`: main CLI entrypoint
- `healthcheck.sh`: machine-wide shell checks
- `dashboard.html`: local dashboard UI
- `codex_output.schema.json`: structured Codex output schema
- `defendos.env.example`: safe config template
- `systemd/*.service.tpl`: systemd unit templates
- `systemd/*.timer`: systemd timers
- `scripts/install-systemd.sh`: installs rendered systemd units for the current checkout path
- `scripts/smoke-test.sh`: local smoke test

The repository is publication-safe by default:

- runtime secrets stay in `defendos.env`
- runtime logs and state stay in `state/`
- both are ignored by git

## Requirements

- Linux host
- Python 3.11+
- `bash`
- optional: Codex CLI with `OPENAI_API_KEY`
- optional: Resend or SMTP for outbound mail
- optional: Resend Receiving or IMAP for inbound commands

## Quick start

```bash
cp defendos.env.example defendos.env
chmod 600 defendos.env
```

Set at least:

- `DEFENDOS_ALERT_EMAIL_TO`
- `DEFENDOS_INBOX_ADDRESS`
- `DEFENDOS_ALLOWED_SENDERS`
- `DEFENDOS_TRUSTED_LOGIN_IPS`
- `RESEND_API_KEY` or `DEFENDOS_SMTP_*`
- `DEFENDOS_IMAP_*` or another inbound provider path

If you want DefendOS to reuse secrets already present elsewhere on the machine, set:

```bash
DEFENDOS_EXTERNAL_ENV_FILES=/path/to/app-one/.env,/path/to/app-two/.env
```

## Manual usage

Run a scheduled-style check:

```bash
python3 ./defendos.py healthcheck
```

Dry-run the healthcheck without Codex or email:

```bash
python3 ./defendos.py healthcheck --skip-codex --no-email
```

Poll the inbox once:

```bash
python3 ./defendos.py poll-inbox
```

Launch the local dashboard:

```bash
python3 ./defendos.py serve
```

Run the smoke test:

```bash
./scripts/smoke-test.sh
```

## Email trigger format

Send an email to the inbox address configured in `DEFENDOS_INBOX_ADDRESS` from an approved sender.

Example subject:

```text
defendos: run a full system audit
```

Example body line:

```text
defendos: verify root ssh logins and unexpected public ports
```

DefendOS will:

1. Run the machine healthcheck.
2. Ask Codex to investigate if enabled.
3. Reply by email in the same thread.

## Systemd install

Render and install the systemd units for the current checkout path:

```bash
./scripts/install-systemd.sh
```

This installs:

- `defendos-healthcheck.timer`
- `defendos-mailbox-poller.timer`
- `defendos-dashboard.service`

Check status:

```bash
systemctl status --no-pager defendos-healthcheck.timer defendos-mailbox-poller.timer defendos-dashboard.service
```

## Notes

- Run it as `root` if you want full visibility into auth logs, fail2ban, root sessions, and other privileged data.
- Codex is launched in read-only mode by default.
- Scheduled runs use a shorter Codex timeout by default so the timer does not remain blocked too long.
- Duplicate scheduled alerts are suppressed for a configurable window.
- Email commands are accepted only from approved senders.
