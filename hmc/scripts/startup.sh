#!/usr/bin/env bash

set -e

[ $EUID -ne 0 ] && echo "run as root" >&2 && exit 1


cat <<'EOF' >/etc/systemd/system/akiranet_hmc.service
[Unit]
Description=AkiraNET HMC service
[Service]
ExecStart=/bin/sh /home/test/workplace/hmc/load.sh
[Install]
WantedBy=multi-user.target
EOF

systemctl enable akiranet_hmc.service

