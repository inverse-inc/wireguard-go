#!/bin/bash

rm -fr build/

mkdir -p build/Wireguard.app
mkdir build/Wireguard.app/Contents
mkdir build/Wireguard.app/Contents/MacOS
mkdir build/Wireguard.app/Contents/Resources
mkdir build/Wireguard.app/Contents/PlugIns

cp Info.plist build/Wireguard.app/Contents

cp ../macoswrapper/macoswrapper build/Wireguard.app/Contents/MacOS/Wireguard
cp wrapper.sh build/Wireguard.app/Contents/MacOS/wrapper
cp ../wireguard-go build/Wireguard.app/Contents/MacOS/

cp wireguard.icns build/Wireguard.app/Contents/Resources/

codesign --deep --force --verbose --sign Inverse build/Wireguard.app

create-dmg \
  --volname "Wireguard Installer" \
  --background "installer_background.png" \
  --window-pos 200 120 \
  --window-size 800 400 \
  --icon-size 100 \
  --icon "Wireguard.app" 200 190 \
  --hide-extension "Wireguard.app" \
  --app-drop-link 600 185 \
  "Wireguard-Installer.dmg" \
  "build/"
