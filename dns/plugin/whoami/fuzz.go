// +build gofuzz

package whoami

import (
	"github.com/inverse-inc/wireguard-go/dns/plugin/pkg/fuzz"
)

// Fuzz fuzzes cache.
func Fuzz(data []byte) int {
	w := Whoami{}
	return fuzz.Do(w, data)
}
