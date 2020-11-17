#!/bin/bash

if ! [ -f .deps/prepared ]; then
  mkdir .deps
  cd .deps
  git clone https://github.com/create-dmg/create-dmg.git || exit 1
  cd -
  touch .deps/prepared
fi

rm -fr build/

mkdir -p "build/PacketFence Zero Trust Client.app"
mkdir "build/PacketFence Zero Trust Client.app/Contents"
mkdir "build/PacketFence Zero Trust Client.app/Contents/MacOS"
mkdir "build/PacketFence Zero Trust Client.app/Contents/Resources"
mkdir "build/PacketFence Zero Trust Client.app/Contents/PlugIns"

cp Info.plist "build/PacketFence Zero Trust Client.app/Contents"

cp ../amd64/traywrapper "build/PacketFence Zero Trust Client.app/Contents/MacOS/PacketFenceZeroTrustClient"
cp ../amd64/guiwrapper "build/PacketFence Zero Trust Client.app/Contents/MacOS/guiwrapper"
cp ../amd64/wireguard "build/PacketFence Zero Trust Client.app/Contents/MacOS/wireguard-go"

cp packetfence-zero-trust-client.icns "build/PacketFence Zero Trust Client.app/Contents/Resources/"

codesign --deep --force --verbose --sign Inverse "build/PacketFence Zero Trust Client.app"

rm -fr dist/
mkdir dist/

./.deps/create-dmg/create-dmg \
  --volname "PacketFence Zero Trust Client Installer" \
  --background "installer_background.png" \
  --window-pos 200 120 \
  --window-size 800 400 \
  --icon-size 100 \
  --icon "PacketFence Zero Trust Client.app" 200 190 \
  --hide-extension "PacketFence Zero Trust Client.app" \
  --app-drop-link 600 185 \
  "dist/PacketFence-Zero-Trust-Client-Installer.dmg" \
  "build/"
