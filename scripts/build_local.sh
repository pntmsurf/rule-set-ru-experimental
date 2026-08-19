#!/usr/bin/env bash
# Локальный аналог .github/workflows/build.yaml — делает ровно то же самое,
# что и CI, чтобы можно было проверить сборку до пуша.
set -euo pipefail

MIHOMO_VERSION="v1.19.29"
SINGBOX_VERSION="v1.9.3"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "== Root: $ROOT_DIR"
echo "== Work: $WORK_DIR"

mkdir -p "$ROOT_DIR/release"
rm -f "$ROOT_DIR"/release/*.mrs "$ROOT_DIR"/release/*.srs "$ROOT_DIR"/release/*.dat

# --- mihomo (.mrs) ---
echo "== Downloading mihomo $MIHOMO_VERSION"
wget -q -O "$WORK_DIR/mihomo.gz" \
  "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VERSION}/mihomo-linux-amd64-${MIHOMO_VERSION}.gz"
gunzip -f "$WORK_DIR/mihomo.gz"
chmod +x "$WORK_DIR/mihomo"

echo "== Converting domain rulesets to .mrs"
for file in "$ROOT_DIR"/src/domains/*.txt; do
  name=$(basename "$file" .txt)
  if ! grep -qE '^[^#[:space:]]' "$file"; then
    echo "  !! $file пуст"
    continue
  fi
  "$WORK_DIR/mihomo" convert-ruleset domain text "$file" "$ROOT_DIR/release/${name}.mrs"
done

echo "== Converting ip rulesets to .mrs"
for file in "$ROOT_DIR"/src/ips/*.txt; do
  name=$(basename "$file" .txt)
  if ! grep -qE '^[^#[:space:]]' "$file"; then
    echo "  !! $file пуст"
    continue
  fi
  case "$name" in
    *-ip) outname="$name" ;;
    *) outname="${name}-ip" ;;
  esac
  "$WORK_DIR/mihomo" convert-ruleset ipcidr text "$file" "$ROOT_DIR/release/${outname}.mrs"
done

# --- sing-box (.srs, via build_srs.go which shells out to sing-box) ---
echo "== Downloading sing-box $SINGBOX_VERSION"
wget -q -O "$WORK_DIR/sing-box.tar.gz" \
  "https://github.com/SagerNet/sing-box/releases/download/${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION#v}-linux-amd64.tar.gz"
tar -xzf "$WORK_DIR/sing-box.tar.gz" -C "$WORK_DIR"
export PATH="$WORK_DIR/sing-box-${SINGBOX_VERSION#v}-linux-amd64:$PATH"

# --- xray (.dat) + sing-box (.srs) ---
echo "== Running Go builders (geosite.dat, geoip.dat, .srs)"
(
  cd "$ROOT_DIR/scripts"
  go run build_geosite.go
  go run build_geoip.go
  go run build_srs.go
)

echo "== Done. Output in $ROOT_DIR/release/"
ls -la "$ROOT_DIR/release/"