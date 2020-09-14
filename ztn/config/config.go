package config

import (
	"bufio"
	"bytes"
	"fmt"

	"github.com/inverse-inc/wireguard-go/device"
)

func SetConfig(device *device.Device, k, v string) {
	device.IpcSetOperation(bufio.NewReader(bytes.NewBufferString(fmt.Sprintf("%s=%s", k, v))))
}

func SetConfigMulti(device *device.Device, conf string) {
	device.IpcSetOperation(bufio.NewReader(bytes.NewBufferString(conf)))
}
