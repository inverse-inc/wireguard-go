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

type Ipv4NetworkMask struct {
	Network, Mask uint32
}

func (nm Ipv4NetworkMask) Match(ip uint32) bool {
	return (ip & nm.Mask) == nm.Network
}
