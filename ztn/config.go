package ztn

import (
	"bufio"
	"bytes"
	"fmt"

	"golang.zx2c4.com/wireguard/device"
)

func SetConfig(device *device.Device, k, v string) {
	device.IpcSetOperation(bufio.NewReader(bytes.NewBufferString(fmt.Sprintf("%s=%s", k, v))))
}

func SetConfigMulti(device *device.Device, conf string) {
	device.IpcSetOperation(bufio.NewReader(bytes.NewBufferString(conf)))
}
