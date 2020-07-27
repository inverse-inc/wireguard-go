package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/fingerbank/processor/sharedutils"
)

func setConfig(device *device.Device, k, v string) {
	device.IpcSetOperation(bufio.NewReader(bytes.NewBufferString(fmt.Sprintf("%s=%s", k, v))))
}

func setConfigMulti(device *device.Device, conf string) {
	device.IpcSetOperation(bufio.NewReader(bytes.NewBufferString(conf)))
}

func keyToHex(b64 string) string {
	data, err := base64.StdEncoding.DecodeString(b64)
	sharedutils.CheckError(err)
	return hex.EncodeToString(data)
}
