// +build gofuzz

package chaos

import (
	"github.com/inverse-inc/wireguard-go/dns/plugin/pkg/fuzz"
)

// Fuzz fuzzes cache.
func Fuzz(data []byte) int {
	c := Chaos{}
	return fuzz.Do(c, data)
}
