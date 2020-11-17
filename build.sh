#!/bin/bash

if [ -z "$GOOS" ]; then
	GOOS=linux
fi

if ! [ -f .deps/prepared ]; then
  mkdir .deps
  curl -L https://golang.org/dl/go1.15.1.$GOOS-amd64.tar.gz > .deps/go.tar.gz
  cd .deps/
  tar -xvf go.tar.gz
  cd -
  
  touch .deps/prepared
fi

if [ -z "$BIN_OUTPUT" ]; then
  BIN_OUTPUT=wireguard-go
fi

./.deps/go/bin/go build -v -o $BIN_OUTPUT || exit 1

cd guiwrapper
if [ -z "$GUIWRAPPER_BIN_OUTPUT" ]; then
  GUIWRAPPER_BIN_OUTPUT=guiwrapper
fi

../.deps/go/bin/go build -v -o $GUIWRAPPER_BIN_OUTPUT || exit 1
cd ..

cd traywrapper
if [ -z "$TRAYWRAPPER_BIN_OUTPUT" ]; then
  TRAYWRAPPER_BIN_OUTPUT=traywrapper
fi

../.deps/go/bin/go build -v -o $TRAYWRAPPER_BIN_OUTPUT || exit 1
cd ..
