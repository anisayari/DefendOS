[Unit]
Description=DefendOS mailbox poller
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=__DEFENDOS_ROOT__
Environment=HOME=/root
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 __DEFENDOS_ROOT__/defendos.py poll-inbox
