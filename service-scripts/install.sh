#!/bin/sh
# 由应用经管理员授权以 root 调用：install.sh <应用路径> <允许访问的 uid>。
# 从应用包安装网络服务，并按这份应用的实际签名和发起安装的用户写入服务策略。
set -eu
APP=$1
ALLOWED_UID=$2
case $ALLOWED_UID in ''|*[!0-9]*) echo 'invalid uid' >&2; exit 64 ;; esac
[ "$ALLOWED_UID" -gt 0 ] || { echo 'invalid uid' >&2; exit 64; }
RES="$APP/Contents/Resources"
LABEL=local.staticexit.network
ROOT='/Library/Application Support/StaticExitManagerService'
HELPER="/Library/PrivilegedHelperTools/$LABEL"
PLIST="/Library/LaunchDaemons/$LABEL.plist"

/usr/bin/codesign --verify --strict "$APP"
requirement() { /usr/bin/codesign -d -r- "$1" 2>&1 | /usr/bin/sed -n 's/^#* *designated => //p'; }
json_escape() { printf '%s' "$1" | /usr/bin/sed 's/\\/\\\\/g; s/"/\\"/g'; }
CLIENT=$(requirement "$APP")
[ -n "$CLIENT" ] || { echo 'missing app requirement' >&2; exit 65; }
VERSION=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$APP/Contents/Info.plist")

if /bin/launchctl print "system/$LABEL" >/dev/null 2>&1; then
  /bin/launchctl bootout "system/$LABEL" || true
fi
/usr/bin/install -d -o root -g wheel -m 755 "$ROOT" "$ROOT/geodata" /Library/PrivilegedHelperTools
/usr/bin/install -o root -g wheel -m 755 "$RES/service/$LABEL" "$HELPER"
/usr/bin/install -o root -g wheel -m 755 "$RES/mihomo" "$ROOT/mihomo"
/usr/bin/install -o root -g wheel -m 644 "$RES/LICENSE-mihomo" "$ROOT/LICENSE-mihomo"
/usr/bin/install -o root -g wheel -m 644 "$RES/geodata/geosite.dat" "$RES/geodata/Country.mmdb" "$ROOT/geodata/"
/usr/bin/install -o root -g wheel -m 644 "$RES/service/$LABEL.plist" "$PLIST"
/usr/bin/xattr -c "$HELPER" "$ROOT/mihomo" "$PLIST"

HELPER_REQ=$(requirement "$HELPER")
[ -n "$HELPER_REQ" ] || { echo 'missing helper requirement' >&2; exit 65; }
POLICY=$(/usr/bin/mktemp "$ROOT/policy.XXXXXX")
printf '{\n  "uid": %s,\n  "version": "%s",\n  "client_requirement": "%s",\n  "helper_requirement": "%s"\n}\n' \
  "$ALLOWED_UID" "$(json_escape "$VERSION")" "$(json_escape "$CLIENT")" "$(json_escape "$HELPER_REQ")" > "$POLICY"
/usr/sbin/chown root:wheel "$POLICY"
/bin/chmod 644 "$POLICY"
/bin/mv -f "$POLICY" "$ROOT/policy.json"
/bin/launchctl bootstrap system "$PLIST"
