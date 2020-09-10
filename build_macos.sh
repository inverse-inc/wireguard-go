#!/bin/bash

mkdir -p amd64

GOOS=darwin \
  GOARCH=amd64 \
  BIN_OUTPUT=amd64/wireguard \
  MACOSWRAPPER_BIN_OUTPUT=../amd64/macoswrapper \
  GUIWRAPPER_BIN_OUTPUT=../amd64/guiwrapper \
  ./build.sh

