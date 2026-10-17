#!/bin/sh
# Enables TCP BBR congestion control (better throughput on long, lossy routes). Needs root, Linux >= 4.9.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
modprobe tcp_bbr 2>/dev/null || true
cat > /etc/sysctl.d/99-akhavan-bbr.conf <<CONF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
CONF
sysctl --system >/dev/null
echo "congestion control: $(sysctl -n net.ipv4.tcp_congestion_control)"
