package erratic

import "github.com/inverse-inc/wireguard-go/dns/request"

// AutoPath implements the AutoPathFunc call from the autopath plugin.
func (e *Erratic) AutoPath(state request.Request) []string {
	return []string{"a.example.org.", "b.example.org.", ""}
}
