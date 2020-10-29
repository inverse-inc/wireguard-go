package main

//go:generate go run directives_generate.go
//go:generate go run owners_generate.go

import (
	_ "github.com/inverse-inc/wireguard-go/dns/core/plugin" // Plug in CoreDNS.
	"github.com/inverse-inc/wireguard-go/dns/coremain"
)

func main() {
	coremain.Run()
}
