package filter

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/inverse-inc/packetfence/go/unifiedapiclient"
)

func BuildRBACFilter(apiClient *unifiedapiclient.Client) RuleFunc {
	return func(data []byte) RuleCmd {
		spew.Dump(data)
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
			ip4 := ip4Layer.(*layers.IPv4)
			spew.Dump(ip4.SrcIP, ip4.DstIP)
		} else {
			fmt.Println("Not an ipv4 packet")
		}
		return Permit
	}
}
