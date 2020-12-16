package auto

import (
	"github.com/inverse-inc/wireguard-go/dns/plugin/transfer"

	"github.com/miekg/dns"
)

// Transfer implements the transfer.Transfer interface.
func (a Auto) Transfer(zone string, serial uint32) (<-chan []dns.RR, error) {
	a.Zones.RLock()
	z, ok := a.Zones.Z[zone]
	a.Zones.RUnlock()

	if !ok || z == nil {
		return nil, transfer.ErrNotAuthoritative
	}
	return z.Transfer(serial)
}
