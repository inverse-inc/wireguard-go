package loadbalance

import (
	"fmt"

	"github.com/inverse-inc/coredns-caddy"
	"github.com/inverse-inc/wireguard-go/dns/core/dnsserver"
	"github.com/inverse-inc/wireguard-go/dns/plugin"
	clog "github.com/inverse-inc/wireguard-go/dns/plugin/pkg/log"
)

var log = clog.NewWithPlugin("loadbalance")

func init() { plugin.Register("loadbalance", setup) }

func setup(c *caddy.Controller) error {
	err := parse(c)
	if err != nil {
		return plugin.Error("loadbalance", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return RoundRobin{Next: next}
	})

	return nil
}

func parse(c *caddy.Controller) error {
	for c.Next() {
		args := c.RemainingArgs()
		switch len(args) {
		case 0:
			return nil
		case 1:
			if args[0] != "round_robin" {
				return fmt.Errorf("unknown policy: %s", args[0])

			}
			return nil
		}
	}
	return c.ArgErr()
}
