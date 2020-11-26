package any

import (
	"github.com/inverse-inc/coredns-caddy"
	"github.com/inverse-inc/wireguard-go/dns/core/dnsserver"
	"github.com/inverse-inc/wireguard-go/dns/plugin"
)

func init() { plugin.Register("any", setup) }

func setup(c *caddy.Controller) error {
	a := Any{}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		a.Next = next
		return a
	})

	return nil
}
