#!/bin/sh
# 由应用退出前以普通用户身份调用：update.sh <应用进程 PID> <已校验的 dmg> <当前应用路径>。
# 等应用退出后挂载 dmg、校验签名并替换应用，再重新打开；任何一步失败都保留并重新打开原应用。
set -eu
PID=$1
DMG=$2
TARGET=$3
NAME='静态出口管理器独立版.app'
MOUNT=$(/usr/bin/mktemp -d /tmp/static-exit-update.XXXXXX)
finish() {
  status=$?
  /usr/bin/hdiutil detach "$MOUNT" -quiet 2>/dev/null || true
  /bin/rmdir "$MOUNT" 2>/dev/null || true
  /bin/rm -rf "$TARGET.updating"
  if [ ! -d "$TARGET" ] && [ -d "$TARGET.old" ]; then /bin/mv "$TARGET.old" "$TARGET"; fi
  [ "$status" -eq 0 ] && /bin/rm -rf "$TARGET.old" "$DMG"
  /usr/bin/open "$TARGET"
}
trap finish EXIT

while /bin/kill -0 "$PID" 2>/dev/null; do /bin/sleep 0.3; done
/usr/bin/hdiutil attach "$DMG" -nobrowse -readonly -noautoopen -mountpoint "$MOUNT" -quiet
/usr/bin/codesign --verify --deep --strict "$MOUNT/$NAME"
/usr/bin/ditto "$MOUNT/$NAME" "$TARGET.updating"
/bin/rm -rf "$TARGET.old"
/bin/mv "$TARGET" "$TARGET.old"
/bin/mv "$TARGET.updating" "$TARGET"
