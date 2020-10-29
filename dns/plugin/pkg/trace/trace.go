package trace

import (
	"github.com/inverse-inc/wireguard-go/dns/plugin"
	ot "github.com/opentracing/opentracing-go"
)

// Trace holds the tracer and endpoint info
type Trace interface {
	plugin.Handler
	Tracer() ot.Tracer
}
