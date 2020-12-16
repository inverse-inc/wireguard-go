package metrics

import (
	"context"

	"github.com/inverse-inc/wireguard-go/dns/plugin"
	"github.com/inverse-inc/wireguard-go/dns/plugin/metrics/vars"
	"github.com/inverse-inc/wireguard-go/dns/plugin/pkg/dnstest"
	"github.com/inverse-inc/wireguard-go/dns/plugin/pkg/rcode"
	"github.com/inverse-inc/wireguard-go/dns/request"

	"github.com/miekg/dns"
)

// ServeDNS implements the Handler interface.
func (m *Metrics) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	qname := state.QName()
	zone := plugin.Zones(m.ZoneNames()).Matches(qname)
	if zone == "" {
		zone = "."
	}

	// Record response to get status code and size of the reply.
	rw := dnstest.NewRecorder(w)
	status, err := plugin.NextOrFailure(m.Name(), m.Next, ctx, rw, r)

	vars.Report(WithServer(ctx), state, zone, rcode.ToString(rw.Rcode), rw.Len, rw.Start)

	return status, err
}

// Name implements the Handler interface.
func (m *Metrics) Name() string { return "prometheus" }
