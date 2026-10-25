#!/bin/zsh
# 构建自包含应用：内置独立 Python、PyYAML、Mihomo 内核和网络服务安装文件，目标电脑无需 Python/Ruby。
# 用法：./build.sh [目标目录]，默认安装到 ~/Applications。
set -eu
cd "$(dirname "$0")"
VERSION=0.3.12
BUILD=16
DEST="${1:-$HOME/Applications}"
# 独立 Python 来自 uv 管理的 python-build-standalone；也可用 PYTHON_HOME 指定解压后的根目录。
PYTHON_HOME="${PYTHON_HOME:-$(dirname "$(dirname "$(realpath "$(uv python find --managed-python 3.12)")")")}"
[[ -x "$PYTHON_HOME/bin/python3.12" ]] || { print -u2 "找不到独立 Python 3.12，请先执行 uv python install 3.12"; exit 1; }
lipo -archs "$PYTHON_HOME/bin/python3.12" | grep -qw arm64 || { print -u2 "独立 Python 不是 arm64"; exit 1; }
# 仓库只保存 Mihomo 官方发布压缩包；首次构建时解压，并按 vendor/manifest.json 校验。
if [[ ! -x vendor/mihomo ]]; then gunzip -c vendor/mihomo.gz > vendor/mihomo; chmod +x vendor/mihomo; fi
[[ "$(shasum -a 256 vendor/mihomo | cut -d ' ' -f 1)" == "$(sed -n 's/.*"mihomo": "\([0-9a-f]*\)".*/\1/p' vendor/manifest.json)" ]] || { print -u2 "vendor/mihomo 校验失败"; exit 1; }
STAGE=$(mktemp -d /tmp/static-exit-standalone.XXXXXX)
trap 'rm -rf "$STAGE"' EXIT
APP="$STAGE/静态出口管理器独立版.app"
RES="$APP/Contents/Resources"
mkdir -p "$APP/Contents/MacOS" "$RES/geodata" "$RES/service" "$RES/pylib"
cp App.swift "$STAGE/main.swift"
swiftc -swift-version 5 -O -framework SwiftUI -framework Security "$STAGE/main.swift" ServiceClient.swift ServiceProtocol.swift -o "$APP/Contents/MacOS/StaticExitManager"
cp Helper.swift "$STAGE/main.swift"
swiftc -swift-version 5 -O -framework Foundation "$STAGE/main.swift" ServiceProtocol.swift NetworkPolicy.swift -o "$RES/service/local.staticexit.network"
cp backend.py "$RES/backend.py"
cp -R vendor/pylib/yaml vendor/pylib/LICENSE-pyyaml "$RES/pylib/"
# 图标由 make_icon.swift 生成并随源码保存；重新设计后执行 swift make_icon.swift Assets。
cp Assets/AppIcon.icns "$RES/AppIcon.icns"
cp vendor/mihomo vendor/LICENSE-mihomo "$RES/"
cp vendor/geodata/geosite.dat vendor/geodata/Country.mmdb "$RES/geodata/"
cp service-scripts/install.sh "$RES/service/install.sh"

# 只保留后台用到的解释器和标准库，去掉 Tk、测试、pip、头文件等。
PY="$RES/python"
mkdir -p "$PY/bin" "$PY/lib"
cp "$PYTHON_HOME/bin/python3.12" "$PY/bin/python3"
rsync -a --exclude '__pycache__/' \
  --exclude 'test/' --exclude 'idlelib/' --exclude 'tkinter/' --exclude 'turtledemo/' --exclude 'ensurepip/' \
  --exclude 'lib2to3/' --exclude 'pydoc_data/' --exclude 'site-packages/*' --exclude 'config-3.12-darwin/' \
  --exclude 'lib-dynload/_tkinter*' --exclude 'turtle.py' \
  "$PYTHON_HOME/lib/python3.12" "$PY/lib/"
cp "$PYTHON_HOME/lib/python3.12/LICENSE.txt" "$PY/LICENSE-python.txt"
# 独立 Python 的配置和字节码会记录构建机路径（含用户名）：配置改为中性前缀，字节码在应用包内用中性路径重新编译。
NEUTRAL=/opt/static-exit-python
sed -i '' "s|$PYTHON_HOME|$NEUTRAL|g" "$PY/lib/python3.12/_sysconfigdata__darwin_darwin.py"
"$PY/bin/python3" -I -B -m compileall -q -f -j 0 -s "$PY" -p "$NEUTRAL" "$PY/lib/python3.12" >/dev/null
"$PY/bin/python3" -I -B -m compileall -q -f -s "$RES/pylib" -p "$NEUTRAL/pylib" "$RES/pylib" >/dev/null

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleExecutable</key><string>StaticExitManager</string><key>CFBundleIdentifier</key><string>local.staticexit.standalone</string><key>CFBundleName</key><string>静态出口管理器独立版</string><key>CFBundleIconFile</key><string>AppIcon</string><key>CFBundleVersion</key><string>$BUILD</string><key>CFBundleShortVersionString</key><string>$VERSION</string><key>LSMinimumSystemVersion</key><string>14.0</string><key>NSHighResolutionCapable</key><true/></dict></plist>
PLIST
cat > "$RES/service/local.staticexit.network.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>local.staticexit.network</string>
<key>ProgramArguments</key><array><string>/Library/PrivilegedHelperTools/local.staticexit.network</string></array>
<key>MachServices</key><dict><key>local.staticexit.network</key><true/></dict>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ProcessType</key><string>Background</string>
<key>Umask</key><integer>63</integer><key>ExitTimeOut</key><integer>15</integer>
<key>AbandonProcessGroup</key><false/>
</dict></plist>
PLIST
xattr -cr "$APP"
# 临时签名：先签内部每个 Mach-O，再签整个应用。服务策略在目标电脑安装时按这份签名生成。
find "$RES" -type f \( -name '*.so' -o -name '*.dylib' -o -perm -u+x \) -print0 | while IFS= read -r -d '' file; do
  if file -b "$file" | grep -q '^Mach-O'; then codesign --force --sign - "$file"; fi
done
codesign --force --sign - "$APP"
mkdir -p "$DEST"
rm -rf "$DEST/静态出口管理器独立版.app"
ditto --norsrc --noextattr --noqtn "$APP" "$DEST/静态出口管理器独立版.app"
codesign --verify --deep --strict "$DEST/静态出口管理器独立版.app"
print "$DEST/静态出口管理器独立版.app"
