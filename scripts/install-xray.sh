#!/bin/sh
# Installs the Xray binary to /usr/local/bin (for running the panel WITHOUT Docker). Verifies SHA-256.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
VERSION="${XRAY_VERSION:-v26.3.27}"
case "$(uname -m)" in
  x86_64|amd64) A=64 ;;
  aarch64|arm64) A=arm64-v8a ;;
  *) echo "unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac
U="https://github.com/XTLS/Xray-core/releases/download/${VERSION}/Xray-linux-${A}.zip"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
command -v unzip >/dev/null || { echo "install unzip first (apt install unzip)" >&2; exit 1; }
curl -fsSL -o "$T/x.zip" "$U"
curl -fsSL -o "$T/x.dgst" "$U.dgst"
WANT="$(sed -n 's/^SHA2-256= *//p' "$T/x.dgst")"
[ -n "$WANT" ] || { echo "could not read checksum" >&2; exit 1; }
echo "$WANT  $T/x.zip" | sha256sum -c -
unzip -q -o "$T/x.zip" xray -d "$T"
install -m 0755 "$T/xray" /usr/local/bin/xray
/usr/local/bin/xray version | head -1
