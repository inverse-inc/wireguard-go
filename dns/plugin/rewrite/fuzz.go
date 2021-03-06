// +build gofuzz

package rewrite

import (
	"github.com/inverse-inc/coredns-caddy"
	"github.com/inverse-inc/wireguard-go/dns/plugin/pkg/fuzz"
)

// Fuzz fuzzes rewrite.
func Fuzz(data []byte) int {
	c := caddy.NewTestController("dns", "rewrite edns0 subnet set 24 56")
	rules, err := rewriteParse(c)
	if err != nil {
		return 0
	}
	r := Rewrite{Rules: rules}

	return fuzz.Do(r, data)
}
