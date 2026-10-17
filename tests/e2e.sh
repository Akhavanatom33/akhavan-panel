#!/bin/sh
# End-to-end: panel -> real Xray (Reality) -> sing-box client -> internet. Usage: tests/e2e.sh node|python
# Needs: xray, sing-box, curl, node, python3; env XRAY_BIN and SINGBOX_BIN, CLIENT_DIR (Windows-client source dir).
KIND=${1:-node}
D=${DATA_DIR:-/tmp/e2e-data}; rm -rf "$D"; mkdir -p "$D"
export DATA_DIR=$D PANEL_TLS=off PANEL_PORT=19443 PANEL_BIND=127.0.0.1 REALITY_PORT=24443 REALITY_SNI=github.com PUBLIC_HOST=127.0.0.1 ADMIN_PASS=TestPass12345 PANEL_PATH=e2etest
ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [ "$KIND" = node ]; then (cd "$ROOT" && setsid node node/server.js >/tmp/e2e-panel.log 2>&1 </dev/null &); else (cd "$ROOT/python" && setsid python3 app.py >/tmp/e2e-panel.log 2>&1 </dev/null &); fi
sleep 3
B=http://127.0.0.1:19443/e2etest; J=/tmp/e2e-cj; H='x-akh: 1'; T='content-type: application/json'
curl -s -c $J -X POST $B/api/login -H "$H" -H "$T" -d '{"username":"admin","password":"TestPass12345"}' >/dev/null
LINK=$(curl -s -b $J -X POST $B/api/clients -H "$H" -H "$T" -d '{"name":"e2e"}' | python3 -c "import sys,json; d=json.load(sys.stdin); print([c for c in d['clients'] if c['name']=='e2e'][0]['links'][0]['url'])")
CID=$(curl -s -b $J $B/api/state | python3 -c "import sys,json; d=json.load(sys.stdin); print([c for c in d['clients'] if c['name']=='e2e'][0]['id'])")
(cd "$CLIENT_DIR" && node test/e2e-reality-gen.js "$LINK")
setsid "$SINGBOX_BIN" run -c /tmp/e2e-reality.json >/tmp/e2e-sb.log 2>&1 </dev/null &
sleep 3
P="-x http://127.0.0.1:10812 --max-time 20"
echo "[$KIND] first connection : $(curl -s -o /dev/null -w '%{http_code} %{time_total}s' $P https://pypi.org/)"
echo "[$KIND] 10 MB+ download   : $(curl -s -o /dev/null -w '%{http_code} %{size_download}B %{speed_download}B/s' $P -L https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip)"
curl -s -o /dev/null -b $J -X PATCH $B/api/clients/$CID -H "$H" -H "$T" -d '{"name":"e2e"}'   # any commit flushes xray counters into the panel
echo "[$KIND] panel counters    : $(curl -s -b $J $B/api/state | python3 -c "import sys,json; d=json.load(sys.stdin); c=[c for c in d['clients'] if c['name']=='e2e'][0]; print('down=%d up=%d' % (c['down'], c['up']))")"
curl -s -o /dev/null -b $J -X PATCH $B/api/clients/$CID -H "$H" -H "$T" -d '{"enabled":false}'
pkill -x sing-box; sleep 1; setsid "$SINGBOX_BIN" run -c /tmp/e2e-reality.json >/tmp/e2e-sb2.log 2>&1 </dev/null &
sleep 3
echo "[$KIND] client disabled   : $(curl -s -o /dev/null -w '%{http_code}' $P https://pypi.org/) (000 = blocked, as expected)"
curl -s -o /dev/null -b $J -X PATCH $B/api/clients/$CID -H "$H" -H "$T" -d '{"enabled":true}'
sleep 2
echo "[$KIND] client re-enabled : $(curl -s -o /dev/null -w '%{http_code} %{time_total}s' $P https://pypi.org/)"
pkill -x sing-box; pkill -x xray; pkill -x node; pkill -x python3
