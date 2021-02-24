package filter

import ()

type RuleCmd int

const (
	Skip   RuleCmd = iota
	Deny           = iota
	Permit         = iota
)

type Rules []RuleFunc

func (rules Rules) PassDefaultDeny(p []byte) bool {
    if len(rules) == 0 {
        return true
    }

	for _, rule := range rules {
		cmd := rule(p)
		if cmd != Skip {
			return cmd == Permit
		}
	}

	return false
}

func (rules Rules) PassDefaultPermit(p []byte) bool {
    if len(rules) == 0 {
        return true
    }

	for _, rule := range rules {
		cmd := rule(p)
		if cmd != Skip {
			return cmd == Permit
		}
	}

	return true
}

func (rules Rules) Filter(p []byte) error {
    if rules.PassDefaultDeny(p) {
        return nil
    }

    return ErrDenyAll
}

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

func protoRule(proto byte, cmd RuleCmd) RuleFunc {
	return RuleFunc(func(p []byte) RuleCmd {
		if p[9] == proto {
			return cmd
		}

		return Skip
	})
}

func toIpv4(a, b, c, d uint8) uint32 {
	return (uint32(a) << 24) | (uint32(b) << 16) | (uint32(c) << 8) | uint32(d)
}

func PermitSrcIpRule(network, mask uint32) RuleFunc {
	return singleIpRule(Ipv4NetworkMask{network, mask}, Permit, 12)
}

func DenySrcIpRule(network, mask uint32) RuleFunc {
	return singleIpRule(Ipv4NetworkMask{network, mask}, Deny, 12)
}

func PermitDstIpRule(network, mask uint32) RuleFunc {
	return singleIpRule(Ipv4NetworkMask{network, mask}, Permit, 16)
}

func DenyDstIpRule(network, mask uint32) RuleFunc {
	return singleIpRule(Ipv4NetworkMask{network, mask}, Deny, 16)
}

func portProtoRule(portRule portOp, proto byte, cmd RuleCmd, offset int) RuleFunc {
	return RuleFunc(func(p []byte) RuleCmd {
		if proto == p[9] {
			hlength := (p[0] & 0x0F) << 2
			data := p[hlength:]
			if portRule.Match(data, offset) {
				return cmd
			}
		}

		return Skip
	})
}

func singleIpRule(networkMask Ipv4NetworkMask, cmd RuleCmd, offset int) RuleFunc {
	return RuleFunc(func(p []byte) RuleCmd {
		if networkMask.MatchBytes(p, offset) {
			return cmd
		}

		return Skip
	})
}

func netmaskProtoRule(nm Ipv4NetworkMask, proto byte, cmd RuleCmd, offset int) RuleFunc {
	return RuleFunc(func(p []byte) RuleCmd {
		if p[9] == proto && nm.MatchBytes(p, offset) {
			return cmd
		}

		return Skip
	})
}

func srcDstProtoRule(src, dst Ipv4NetworkMask, proto byte, cmd RuleCmd) RuleFunc {
	return RuleFunc(func(p []byte) RuleCmd {
		if proto == p[9] && src.MatchSrc(p) && dst.MatchDst(p) {
			return cmd
		}

		return Skip
	})
}

func toPort(a, b byte) uint16 {
	return (uint16(a) << 8) | uint16(b)
}

func srcDstProtoPortRule(src, dst Ipv4NetworkMask, proto byte, port uint16, cmd RuleCmd, offset int) RuleFunc {
	return RuleFunc(func(p []byte) RuleCmd {
		if proto == p[9] {
			hlength := (p[0] & 0x0F) << 2
			data := p[hlength:]
			if src.MatchSrc(p) && dst.MatchDst(p) && toPort(data[offset], data[offset+1]) == port {
				return cmd
			}
		}

		return Skip
	})
}

func srcDstProtoSrcPortDstPort(src, dst Ipv4NetworkMask, proto byte, srcPort, dstPort portOp, cmd RuleCmd) RuleFunc {
	return RuleFunc(func(p []byte) RuleCmd {
		if proto == p[9] {
			hlength := (p[0] & 0x0F) << 2
			data := p[hlength:]
			if src.MatchSrc(p) && dst.MatchDst(p) && srcPort.Match(data, 0) && dstPort.Match(data, 2) {
				return cmd
			}
		}

		return Skip
	})
}

func srcDstRule(src, dst Ipv4NetworkMask, cmd RuleCmd) RuleFunc {
	return RuleFunc(func(p []byte) RuleCmd {
		if src.MatchSrc(p) && dst.MatchDst(p) {
			return cmd
		}

		return Skip
	})
}

func icmpRuleRule(rule icmpRule, cmd RuleCmd) RuleFunc {
	switch {
	default:
		return protoRule(1, cmd)
	case rule.iType != invalidIcmpTypeCode && rule.code != invalidIcmpTypeCode:
		return RuleFunc(func(p []byte) RuleCmd {
			if p[9] == 1 {
				hlength := (p[0] & 0x0F) << 2
				data := p[hlength:]
				if data[0] == byte(rule.iType) && data[1] == byte(rule.code) {
					return cmd
				}
			}

			return Skip
		})
	case rule.iType != invalidIcmpTypeCode && rule.code == invalidIcmpTypeCode:
		return RuleFunc(func(p []byte) RuleCmd {
			if p[9] == 1 {
				hlength := (p[0] & 0x0F) << 2
				data := p[hlength:]
				if data[0] == byte(rule.iType) {
					return cmd
				}
			}

			return Skip
		})
	case rule.iType == invalidIcmpTypeCode && rule.code != invalidIcmpTypeCode:
		return RuleFunc(func(p []byte) RuleCmd {
			if p[9] == 1 {
				hlength := (p[0] & 0x0F) << 2
				data := p[hlength:]
				if data[1] == byte(rule.code) {
					return cmd
				}
			}

			return Skip
		})
	}
}

func netMaskIcmpRuleRule(nm Ipv4NetworkMask, rule icmpRule, cmd RuleCmd, offset int) RuleFunc {
	switch {
	default:
		return netmaskProtoRule(nm, 1, cmd, offset)
	case rule.iType != invalidIcmpTypeCode && rule.code != invalidIcmpTypeCode:
		return RuleFunc(func(p []byte) RuleCmd {
			if p[9] == 1 {
				if nm.MatchBytes(p, offset) {
					hlength := (p[0] & 0x0F) << 2
					data := p[hlength:]
					if data[0] == byte(rule.iType) && data[1] == byte(rule.code) {
						return cmd
					}
				}
			}

			return Skip
		})
	case rule.iType != invalidIcmpTypeCode && rule.code == invalidIcmpTypeCode:
		return RuleFunc(func(p []byte) RuleCmd {
			if p[9] == 1 {
				if nm.MatchBytes(p, offset) {
					hlength := (p[0] & 0x0F) << 2
					data := p[hlength:]
					if data[0] == byte(rule.iType) {
						return cmd
					}
				}
			}

			return Skip
		})
	case rule.iType == invalidIcmpTypeCode && rule.code != invalidIcmpTypeCode:
		return RuleFunc(func(p []byte) RuleCmd {
			if p[9] == 1 {
				if nm.MatchBytes(p, offset) {
					hlength := (p[0] & 0x0F) << 2
					data := p[hlength:]
					if data[1] == byte(rule.code) {
						return cmd
					}
				}
			}

			return Skip
		})
	}
}

func srcDstIcmpRuleRule(src, dst Ipv4NetworkMask, rule icmpRule, cmd RuleCmd, offset int) RuleFunc {
	switch {
	default:
		return srcDstProtoRule(src, dst, 1, cmd)
	case rule.iType != invalidIcmpTypeCode && rule.code != invalidIcmpTypeCode:
		return RuleFunc(func(p []byte) RuleCmd {
			if p[9] == 1 {
				if src.MatchSrc(p) && dst.MatchDst(p) {
					hlength := (p[0] & 0x0F) << 2
					data := p[hlength:]
					if data[0] == byte(rule.iType) && data[1] == byte(rule.code) {
						return cmd
					}
				}
			}

			return Skip
		})
	case rule.iType != invalidIcmpTypeCode && rule.code == invalidIcmpTypeCode:
		return RuleFunc(func(p []byte) RuleCmd {
			if p[9] == 1 {
				if src.MatchSrc(p) && dst.MatchDst(p) {
					hlength := (p[0] & 0x0F) << 2
					data := p[hlength:]
					if data[0] == byte(rule.iType) {
						return cmd
					}
				}
			}

			return Skip
		})
	case rule.iType == invalidIcmpTypeCode && rule.code != invalidIcmpTypeCode:
		return RuleFunc(func(p []byte) RuleCmd {
			if p[9] == 1 {
				if src.MatchSrc(p) && dst.MatchDst(p) {
					hlength := (p[0] & 0x0F) << 2
					data := p[hlength:]
					if data[1] == byte(rule.code) {
						return cmd
					}
				}
			}

			return Skip
		})
	}
}

type Ipv4NetworkMask struct {
	Network, Mask uint32
}

func (nm Ipv4NetworkMask) MatchBytes(p []byte, offset int) bool {
	return nm.Match(toIpv4(p[offset], p[offset+1], p[offset+2], p[offset+3]))
}

func (nm Ipv4NetworkMask) MatchSrc(p []byte) bool {
	return nm.MatchBytes(p, SRC_IP_OFFSET)
}

func (nm Ipv4NetworkMask) MatchDst(p []byte) bool {
	return nm.MatchBytes(p, DST_IP_OFFSET)
}

func (nm Ipv4NetworkMask) Match(ip uint32) bool {
	return (ip & nm.Mask) == nm.Network
}

