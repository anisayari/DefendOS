[Unit]
Description=DefendOS scheduled global healthcheck
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
SuccessExitStatus=2
WorkingDirectory=__DEFENDOS_ROOT__
Environment=HOME=/root
Environment=PYTHONUNBUFFERED=1
TimeoutStartSec=infinity
ExecStart=/usr/bin/python3 __DEFENDOS_ROOT__/defendos.py healthcheck
