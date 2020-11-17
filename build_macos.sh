#!/bin/bash

mkdir -p amd64

GOOS=darwin \
  GOARCH=amd64 \
  BIN_OUTPUT=amd64/wireguard \
  GUIWRAPPER_BIN_OUTPUT=../amd64/guiwrapper \
  TRAYWRAPPER_BIN_OUTPUT=../amd64/traywrapper \
  ./build.sh

