package filter

import (
	"context"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/packetfence/go/unifiedapiclient"
	"github.com/inverse-inc/wireguard-go/device"
	"github.com/inverse-inc/wireguard-go/ztn"
	"github.com/patrickmn/go-cache"
)

var rbacAllowCache *cache.Cache

func init() {
	var cacheTime time.Duration
	defaultCacheTime := 30 * time.Minute
	cacheTimeEnv := sharedutils.EnvOrDefault(ztn.EnvRBACIPFilteringCacheTime, defaultCacheTime.String())
	if cacheTimeParsed, err := time.ParseDuration(cacheTimeEnv); err == nil {
		cacheTime = cacheTimeParsed
	} else {
		cacheTime = defaultCacheTime
	}
	rbacAllowCache = cache.New(cacheTime, 1*time.Minute)
}

func BuildRBACFilter(apiClientCtx context.Context, apiClient *unifiedapiclient.Client, logger *device.Logger, mode *uint32) RuleFunc {
	return func(data []byte) RuleCmd {
		//if atomic.LoadUint32(mode) == 0 {
		//	return Permit
		//}
		packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
		if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
			ip4 := ip4Layer.(*layers.IPv4)
			k := fmt.Sprintf("%s->%s", ip4.SrcIP, ip4.DstIP)
			if cacheRes, found := rbacAllowCache.Get(k); found {
				return cacheRes.(RuleCmd)
			} else {
				apiRes := struct {
					Permit bool `json:"permit"`
				}{}
				err := apiClient.Call(apiClientCtx, "GET", fmt.Sprintf("/api/v1/remote_clients/allowed_ip_communication?src_ip=%s&dst_ip=%s", ip4.SrcIP, ip4.DstIP), &apiRes)
				var res RuleCmd
				if err != nil {
					logger.Info.Println("(API ERR) Denying access from", ip4.SrcIP, "to", ip4.DstIP)
					res = Deny
				} else if !apiRes.Permit {
					logger.Info.Println("(Access Denied) Denying access from", ip4.SrcIP, "to", ip4.DstIP)
					res = Deny
				} else {
					logger.Info.Println("Allowing access from", ip4.SrcIP, "to", ip4.DstIP)
					res = Permit
				}
				rbacAllowCache.SetDefault(k, res)
				return res
			}
		} else {
			return Permit
		}
	}
}
