package filter

type RuleCmd int

const (
	Skip   RuleCmd = iota
	Deny           = iota
	Permit         = iota
)

type RuleFunc func([]byte) RuleCmd

func RulePermit([]byte) RuleCmd {
	return Permit
}

func RuleDeny([]byte) RuleCmd {
	return Deny
}

func PermitAllRule() RuleFunc {
	return RuleFunc(RulePermit)
}

func DenyAllRule() RuleFunc {
	return RuleFunc(RuleDeny)
}

func PermitAllTcpRule() RuleFunc {
	return PermitAllProto(tcpProtocol)
}

func PermitAllUdpRule() RuleFunc {
	return PermitAllProto(udpProtocol)
}

func PermitAllIcmpRule() RuleFunc {
	return PermitAllProto(icmpProtocol)
}

func PermitAllProto(proto byte) RuleFunc {
	return RuleFunc(func(p []byte) RuleCmd {
		if p[9] == proto {
			return Permit
		}

		return Skip
	})
}

func toIpv4(a, b, c, d uint8) uint32 {
	return (uint32(a) << 24) | (uint32(b) << 16) | (uint32(c) << 8) | uint32(d)
}

func PermitSrcIpRule(network, mask uint32) RuleFunc {
	return RuleFunc(func(p []byte) RuleCmd {
		srcIpv4NetworkMask := Ipv4NetworkMask{network, mask}
		if srcIpv4NetworkMask.Match(toIpv4(p[12], p[13], p[14], p[15])) {
			return Permit
		}
		return Skip
	})
}

func DenySrcIpRule(network, mask uint32) RuleFunc {
	return RuleFunc(func(p []byte) RuleCmd {
		srcIpv4NetworkMask := Ipv4NetworkMask{network, mask}
		if srcIpv4NetworkMask.Match(toIpv4(p[12], p[13], p[14], p[15])) {
			return Deny
		}

		return Skip
	})
}

func PermitDstIpRule(network, mask uint32) RuleFunc {
	return RuleFunc(func(p []byte) RuleCmd {
		srcIpv4NetworkMask := Ipv4NetworkMask{network, mask}
		if srcIpv4NetworkMask.Match(toIpv4(p[16], p[17], p[18], p[19])) {
			return Permit
		}
		return Skip
	})
}

func DenyDstIpRule(network, mask uint32) RuleFunc {
	return RuleFunc(func(p []byte) RuleCmd {
		srcIpv4NetworkMask := Ipv4NetworkMask{network, mask}
		if srcIpv4NetworkMask.Match(toIpv4(p[16], p[17], p[18], p[19])) {
			return Deny
		}

		return Skip
	})
}

type Ipv4NetworkMask struct {
	Network, Mask uint32
}

func (nm Ipv4NetworkMask) Match(ip uint32) bool {
	return (ip & nm.Mask) == nm.Network
}
