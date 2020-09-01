// +build !linux android

package device

import (
	"github.com/inverse-inc/wireguard-go/conn"
	"github.com/inverse-inc/wireguard-go/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
