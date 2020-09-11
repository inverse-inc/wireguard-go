#!/bin/bash

mkdir -p amd64

if [ ! -f .deps/prepared ]; then
  if which apt-get; then
    sudo apt-get update
    sudo apt-get install gcc libgl1-mesa-dev xorg-dev libgtk-3-dev libappindicator3-dev -y
  fi
fi

GOOS=linux \
  GOARCH=amd64 \
  BIN_OUTPUT=amd64/wireguard \
  GUIWRAPPER_BIN_OUTPUT=../amd64/guiwrapper \
  TRAYWRAPPER_BIN_OUTPUT=../amd64/traywrapper \
  ./build.sh

