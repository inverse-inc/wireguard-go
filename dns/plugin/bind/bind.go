// Package bind allows binding to a specific interface instead of bind to all of them.
package bind

import "github.com/inverse-inc/wireguard-go/dns/plugin"

func init() { plugin.Register("bind", setup) }
