#!/bin/sh
# Build ReaDisassembler.app (native macOS GUI) with swiftc — no Xcode
# project needed.  Usage: ./gui/build_app.sh && open gui/ReaDisassembler.app
set -e
cd "$(dirname "$0")/.."
APP="gui/ReaDisassembler.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
swiftc -O -o "$APP/Contents/MacOS/ReaDisassembler" gui/ReaDisassemblerApp.swift
cp gui/Info.plist "$APP/Contents/Info.plist"
printf 'APPL????' > "$APP/Contents/PkgInfo"
codesign -f -s - "$APP" 2>/dev/null || true
echo "built $APP"
