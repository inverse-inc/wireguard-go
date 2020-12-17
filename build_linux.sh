#!/bin/bash

if [ -z "$ARCH" ]; then
	ARCH=amd64
fi

export ARCH=$ARCH

mkdir -p $ARCH

if [ ! -f .deps/prepared ]; then
  if which apt-get; then
    sudo apt-get update
    sudo apt-get install gcc libgl1-mesa-dev xorg-dev libgtk-3-dev libappindicator3-dev -y
  fi
fi

GOOS=linux \
  GOARCH=$ARCH \
  BIN_OUTPUT=$ARCH/wireguard \
  GUIWRAPPER_BIN_OUTPUT=../$ARCH/guiwrapper \
  TRAYWRAPPER_BIN_OUTPUT=../$ARCH/traywrapper \
  ./build.sh

cp util/icon/logo.png $ARCH/

