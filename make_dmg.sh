#!/bin/zsh
# 生成发给朋友的 dmg：应用、「应用程序」快捷方式和安装说明，输出到 dist/。
set -eu
cd "$(dirname "$0")"
VERSION=$(sed -n 's/^VERSION=//p' build.sh)
STAGE=$(mktemp -d /tmp/static-exit-dmg.XXXXXX)
trap 'rm -rf "$STAGE"' EXIT
./build.sh "$STAGE/root" >/dev/null
ln -s /Applications "$STAGE/root/Applications"
cp 安装说明.txt "$STAGE/root/安装说明.txt"
mkdir -p dist
OUT="dist/StaticExitManager-$VERSION-arm64.dmg"
hdiutil create -volname "静态出口管理器 $VERSION" -srcfolder "$STAGE/root" -format UDZO -fs HFS+ -ov "$OUT" >/dev/null
shasum -a 256 "$OUT"
