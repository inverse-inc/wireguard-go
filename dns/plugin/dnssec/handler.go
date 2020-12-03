package dnssec

import (
	"context"

	"github.com/inverse-inc/wireguard-go/dns/plugin"
	"github.com/inverse-inc/wireguard-go/dns/plugin/metrics"
	"github.com/inverse-inc/wireguard-go/dns/request"

	"github.com/miekg/dns"
)

// ServeDNS implements the plugin.Handler interface.
func (d Dnssec) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	do := state.Do()
	qname := state.Name()
	qtype := state.QType()
	zone := plugin.Zones(d.zones).Matches(qname)
	if zone == "" {
		return plugin.NextOrFailure(d.Name(), d.Next, ctx, w, r)
	}

	state.Zone = zone
	server := metrics.WithServer(ctx)

	// Intercept queries for DNSKEY, but only if one of the zones matches the qname, otherwise we let
	// the query through.
	if qtype == dns.TypeDNSKEY {
		for _, z := range d.zones {
			if qname == z {
				resp := d.getDNSKEY(state, z, do, server)
				resp.Authoritative = true
				w.WriteMsg(resp)
				return dns.RcodeSuccess, nil
			}
		}
	}

	if do {
		drr := &ResponseWriter{w, d, server}
		return plugin.NextOrFailure(d.Name(), d.Next, ctx, drr, r)
	}

	return plugin.NextOrFailure(d.Name(), d.Next, ctx, w, r)
}

// Name implements the Handler interface.
func (d Dnssec) Name() string { return "dnssec" }
