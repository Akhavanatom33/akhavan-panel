#!/usr/bin/env bash
# Akhavan Panel installer (Docker).  Usage:  sudo bash install.sh [options]
#   --backend node|python   which backend to run (default: node; they are equivalent)
#   --panel-port N          HTTPS port of the panel            (default 8443)
#   --reality-port N        port of the first VPN server       (default 443)
#   --sni HOST              camouflage site for Reality        (default www.microsoft.com)
#   --host IP_OR_DOMAIN     address written in the links       (default: auto-detect public IP)
#   --name NAME             name of the first server, e.g. Akhavan-DE
#   --country CC            2-letter code for the flag in the app, e.g. DE
#   --bbr                   also enable TCP BBR (faster on long routes)
# Safe to run again: it keeps your data and just rebuilds/updates the container.
set -euo pipefail
cd "$(dirname "$0")"

BACKEND=node PORT=8443 RPORT=443 SNI=www.microsoft.com HOST="" NAME="" COUNTRY="" BBR=0

die() { echo "ERROR: $*" >&2; exit 1; }
usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --backend)      BACKEND="${2:-}"; shift 2 ;;
    --panel-port)   PORT="${2:-}"; shift 2 ;;
    --reality-port) RPORT="${2:-}"; shift 2 ;;
    --sni)          SNI="${2:-}"; shift 2 ;;
    --host)         HOST="${2:-}"; shift 2 ;;
    --name)         NAME="${2:-}"; shift 2 ;;
    --country)      COUNTRY="${2:-}"; shift 2 ;;
    --bbr)          BBR=1; shift ;;
    -h|--help)      usage; exit 0 ;;
    *)              usage; die "unknown option: $1" ;;
  esac
done

case "$BACKEND" in node|python) ;; *) die "--backend must be node or python" ;; esac
case "$PORT$RPORT" in *[!0-9]*) die "ports must be numbers" ;; esac
[ "$(id -u)" -eq 0 ] || die "please run as root:  sudo bash install.sh"

# ---- Docker ----
if ! command -v docker >/dev/null 2>&1; then
  echo ">> Installing Docker (official script from get.docker.com)..."
  command -v curl >/dev/null 2>&1 || die "curl is required (apt install curl)"
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker >/dev/null 2>&1 || true
docker compose version >/dev/null 2>&1 || die "the 'docker compose' plugin is missing; install docker-compose-plugin and retry"

# ---- configuration (.env is only read on the first start) ----
if [ ! -f .env ]; then
  {
    echo "PANEL_PORT=$PORT"
    echo "REALITY_PORT=$RPORT"
    echo "REALITY_SNI=$SNI"
    if [ -n "$HOST" ]; then echo "PUBLIC_HOST=$HOST"; fi
    if [ -n "$NAME" ]; then echo "SERVER_NAME=$NAME"; fi
    if [ -n "$COUNTRY" ]; then echo "COUNTRY=$COUNTRY"; fi
  } > .env
  chmod 600 .env
  echo ">> Wrote .env"
else
  echo ">> Keeping existing .env"
fi
mkdir -p data
chmod 700 data

# ---- warn if the ports are busy (and not by us) ----
if command -v ss >/dev/null 2>&1; then
  for p in "$PORT" "$RPORT"; do
    if ss -ltn "sport = :$p" 2>/dev/null | grep -q LISTEN && ! docker ps --format '{{.Names}}' | grep -q '^akhavan-panel$'; then
      echo "WARNING: TCP port $p is already in use by another program; stop it or choose another port (--panel-port / --reality-port)."
    fi
  done
fi

# ---- start ----
other=python; [ "$BACKEND" = python ] && other=node
docker compose --profile "$other" down >/dev/null 2>&1 || true
echo ">> Building and starting the $BACKEND backend (first build takes a minute)..."
docker compose --profile "$BACKEND" up -d --build

if [ "$BBR" -eq 1 ]; then sh scripts/enable-bbr.sh || echo "WARNING: could not enable BBR"; fi

echo ">> Waiting for the panel..."
i=0
until docker logs akhavan-panel 2>&1 | grep -q "Panel URL"; do
  i=$((i + 1))
  [ "$i" -le 90 ] || { docker logs --tail 30 akhavan-panel 2>&1 || true; die "the panel did not start; see the log above"; }
  sleep 1
done

echo
if [ -f data/CREDENTIALS.txt ]; then
  cat data/CREDENTIALS.txt
else
  docker logs akhavan-panel 2>&1 | grep -E "Panel URL|fingerprint" | tail -2
  echo "(password was shown at the first start; reset it with:  docker compose exec akhavan-panel $( [ "$BACKEND" = node ] && echo 'node server.js' || echo 'python3 app.py' ) --reset-password )"
fi
cat <<MSG

NEXT STEPS
 1. Open these TCP ports in your provider's firewall (and ufw if you use it): $RPORT (VPN) and $PORT (panel).
 2. Open the Panel URL above. The browser warns about the certificate (it is self-signed):
    compare the SHA-256 fingerprint with the one printed above, then continue.
 3. Copy the config link / scan the QR into Akhavan VPN, v2rayNG, Hiddify or Streisand.
 4. Delete data/CREDENTIALS.txt after saving the password.
MSG
