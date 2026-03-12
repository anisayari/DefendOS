[Unit]
Description=DefendOS local dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=__DEFENDOS_ROOT__
Environment=HOME=/root
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 __DEFENDOS_ROOT__/defendos.py serve
Restart=always
RestartSec=5
