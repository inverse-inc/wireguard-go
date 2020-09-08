#!/bin/bash

if ! [ -f .deps/prepared ]; then
  mkdir .deps
  cd .deps
  git clone https://github.com/create-dmg/create-dmg.git || exit 1
  cd -
  touch .deps/prepared
fi

rm -fr build/

mkdir -p build/Wireguard.app
mkdir build/Wireguard.app/Contents
mkdir build/Wireguard.app/Contents/MacOS
mkdir build/Wireguard.app/Contents/Resources
mkdir build/Wireguard.app/Contents/PlugIns

cp Info.plist build/Wireguard.app/Contents

cp ../amd64/macoswrapper build/Wireguard.app/Contents/MacOS/Wireguard
cp wrapper.sh build/Wireguard.app/Contents/MacOS/wrapper
cp ../amd64/wireguard build/Wireguard.app/Contents/MacOS/wireguard-go

cp wireguard.icns build/Wireguard.app/Contents/Resources/

codesign --deep --force --verbose --sign Inverse build/Wireguard.app

rm -fr dist/
mkdir dist/

./.deps/create-dmg/create-dmg \
  --volname "Wireguard Installer" \
  --background "installer_background.png" \
  --window-pos 200 120 \
  --window-size 800 400 \
  --icon-size 100 \
  --icon "Wireguard.app" 200 190 \
  --hide-extension "Wireguard.app" \
  --app-drop-link 600 185 \
  "dist/Wireguard-Installer.dmg" \
  "build/"
