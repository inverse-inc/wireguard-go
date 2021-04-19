package filter

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/inverse-inc/packetfence/go/unifiedapiclient"
)

func BuildRBACFilter(apiClientCtx context.Context, apiClient *unifiedapiclient.Client, mode *uint32) RuleFunc {
	return func(data []byte) RuleCmd {
		if atomic.LoadUint32(mode) == 0 {
			return Permit
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
		if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
			ip4 := ip4Layer.(*layers.IPv4)
			fmt.Println("from", ip4.SrcIP, "to", ip4.DstIP)
			res := struct {
				Permit bool `json:"permit"`
			}{}
			err := apiClient.Call(apiClientCtx, "GET", fmt.Sprintf("/api/v1/remote_clients/allowed_ip_communication?src_ip=%s&dst_ip=%s", ip4.SrcIP, ip4.DstIP), &res)
			if err != nil {
				//TODO: add debounced DEBUG logging for that src+dst IP couple
				return Deny
			}
			if !res.Permit {
				//TODO: add debounced INFO logging for that src+dst IP couple
				return Deny
			}
		}
		return Permit
	}
}
