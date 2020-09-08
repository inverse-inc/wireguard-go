#!/bin/bash


if ! [ -f .deps/prepared ]; then
  mkdir .deps
  wget https://golang.org/dl/go1.15.1.linux-amd64.tar.gz -O .deps/go.tar.gz
  cd .deps/
  tar -xvf go.tar.gz
  cd -
  
  touch .deps/prepared
fi

if [ -z "$BIN_OUTPUT" ]; then
  BIN_OUTPUT=wireguard-go
fi

./.deps/go/bin/go build -v -o $BIN_OUTPUT

cd macoswrapper
if [ -z "$MACOSWRAPPER_BIN_OUTPUT" ]; then
  MACOSWRAPPER_BIN_OUTPUT=macoswrapper
fi

../.deps/go/bin/go build -v -o $MACOSWRAPPER_BIN_OUTPUT

