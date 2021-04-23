package filter

import (
	"strconv"
	"strings"
)

func AclsToRules(acls ...string) Rules {
	rules := []RuleFunc{}
	for _, acl := range acls {
		rule := AclToRule(acl)
		if rule != nil {
			rules = append(rules, rule)
		}
	}

	return rules
}

func AclsToRulesFilter(acls []string, pre, post RuleFunc) func([]byte) error {
	rules := Rules([]RuleFunc{})
	if pre != nil {
		rules = append(rules, pre)
	}
	rules = append(rules, AclsToRules(acls...)...)
	if post != nil {
		rules = append(rules, post)
	}

	return rules.Filter
}

const SRC_IP_OFFSET = 12
const DST_IP_OFFSET = 16

const invalidIcmpTypeCode = int16(-1)

type icmpRule struct {
	iType int16
	code  int16
}

func (r icmpRule) AnyCode() bool {
	return r.code == invalidIcmpTypeCode
}

func (r icmpRule) AnyType() bool {
	return r.iType == invalidIcmpTypeCode
}

func (r icmpRule) Any() bool {
	return r.AnyType() && r.AnyCode()
}

type Ipv4RuleData struct {
	src      Ipv4NetworkMask
	dst      Ipv4NetworkMask
	srcPort  portOp
	dstPort  portOp
	cmd      RuleCmd
	protocol int16
	icmpRule icmpRule
}

func NewIpv4RuleData() Ipv4RuleData {
	return Ipv4RuleData{
		icmpRule: icmpRule{invalidIcmpTypeCode, invalidIcmpTypeCode},
		srcPort:  portOp{op: portOpTrue},
		dstPort:  portOp{op: portOpTrue},
	}
}

func (r *Ipv4RuleData) AnySrcIP() bool {
	return r.src.Network == 0 && r.src.Mask == 0
}

func (r *Ipv4RuleData) AnySrcPort() bool {
	return r.srcPort.op == portOpTrue
}

func (r *Ipv4RuleData) AnyDstIP() bool {
	return r.dst.Network == 0 && r.dst.Mask == 0
}

func (r *Ipv4RuleData) AnyDstPort() bool {
	return r.dstPort.op == portOpTrue
}

func (r *Ipv4RuleData) AnyIp() bool {
	return r.AnySrcIP() && r.AnyDstIP()
}

func (r *Ipv4RuleData) AnyPort() bool {
	return r.AnyDstPort() && r.AnySrcPort()
}

func (r *Ipv4RuleData) AnyProto() bool {
	return r.protocol == allProtocols
}

func AclToRule(acl string) RuleFunc {
	tokens := strings.Fields(acl)
	if len(tokens) < 2 {
		return nil
	}

	if len(tokens) == 2 {
		return twoPartAcl(tokens)
	}

	rule := NewIpv4RuleData()

	token, tokens, ok := nextToken(tokens)
	rule.cmd = Skip
	switch token {
	case "permit":
		rule.cmd = Permit
	case "deny":
		rule.cmd = Deny
	default:
		return nil
	}

	rule.src.Network, rule.src.Mask, tokens, ok = getSource(tokens)
	if ok {
		return singleIpRule(rule.src, rule.cmd, SRC_IP_OFFSET)
	}

	rule.protocol, tokens, ok = getProtocol(tokens)
	if !ok {
		return nil
	}

	rule.src.Network, rule.src.Mask, tokens, ok = getSource(tokens)
	if !ok {
		return nil
	}

	if rule.protocol == 6 || rule.protocol == 17 {
		rule.srcPort.op, rule.srcPort.start, rule.srcPort.end, tokens, ok = getPort(rule.protocol, tokens)
	}

	rule.dst.Network, rule.dst.Mask, tokens, ok = getSource(tokens)
	if !ok {
		return nil
	}

	switch rule.protocol {
	case 6, 17:
		rule.dstPort.op, rule.dstPort.start, rule.dstPort.end, tokens, ok = getPort(rule.protocol, tokens)
	case 1:
		rule.icmpRule, tokens, ok = getIcmpRule(tokens)
	}

	if rule.AnyIp() {
		if rule.AnyProto() {
			if rule.cmd == Permit {
				return PermitAllRule()
			}

			return DenyAllRule()
		}

		if rule.protocol == 1 {
			return icmpRuleRule(rule.icmpRule, rule.cmd)
		}

		if rule.AnyPort() {
			return protoRule(byte(rule.protocol), rule.cmd)
		}

		if rule.AnySrcPort() && !rule.AnyDstPort() {
			return portProtoRule(rule.dstPort, byte(rule.protocol), rule.cmd, 2)
		}

		if !rule.AnySrcPort() && rule.AnyDstPort() {
			return portProtoRule(rule.srcPort, byte(rule.protocol), rule.cmd, 0)
		}

	}

	if rule.AnyProto() {
		if rule.AnySrcIP() && !rule.AnyDstIP() {
			return singleIpRule(rule.dst, rule.cmd, DST_IP_OFFSET)
		}

		if !rule.AnySrcIP() && rule.AnyDstIP() {
			return singleIpRule(rule.src, rule.cmd, SRC_IP_OFFSET)
		}

		return srcDstRule(rule.src, rule.dst, rule.cmd)
	}

	if rule.AnyPort() {
		return srcDstProtoRule(rule.src, rule.dst, byte(rule.protocol), rule.cmd)
	}

	return srcDstProtoSrcPortDstPort(rule.src, rule.dst, byte(rule.protocol), rule.srcPort, rule.dstPort, rule.cmd)
}

func getProtocol(oTokens []string) (int16, []string, bool) {
	token, tokens, ok := nextToken(oTokens)
	if !ok {
		return invalidProtocol, oTokens, false
	}

	if proto, found := protocolLookup[token]; found {
		return proto, tokens, true
	}

	proto, err := strconv.ParseUint(token, 10, 8)
	if err == nil {
		return int16(proto), tokens, true
	}

	return invalidProtocol, oTokens, false
}

const fullMask = uint32(1<<32 - 1)
const allProtocols = int16(256)
const invalidProtocol = -1

var protocolLookup = map[string]int16{
	//	"ahp":    ,
	"eigrp":  88,
	"esp":    50,
	"gre":    47,
	"icmp":   1,
	"igmp":   2,
	"igrp":   9,
	"ip":     allProtocols,
	"ipinip": 94,
	//	"nos":    ,
	"ospf": 89,
	//	"pcp":    ,
	"pim": 103,
	"tcp": 6,
	"udp": 17,
}

const (
	invalidOp   = iota
	portOpEq    = iota
	portOpNeq   = iota
	portOpGt    = iota
	portOpLt    = iota
	portOpRange = iota
	portOpTrue  = iota
)

var validOps = map[string]int{
	"eq":    portOpEq,
	"neq":   portOpNeq,
	"gt":    portOpGt,
	"lt":    portOpLt,
	"range": portOpRange,
}

type portOp struct {
	op    int
	start uint16
	end   uint16
}

func (po portOp) Match(data []byte, offset int) bool {
	switch po.op {
	default:
		return false
	case portOpEq:
		return toPort(data[offset], data[offset+1]) == po.start
	case portOpNeq:
		return toPort(data[offset], data[offset+1]) != po.start
	case portOpGt:
		return toPort(data[offset], data[offset+1]) > po.start
	case portOpLt:
		return toPort(data[offset], data[offset+1]) < po.start
	case portOpRange:
		port := toPort(data[offset], data[offset+1])
		return po.start <= port && port <= po.end
	case portOpTrue:
		return true
	}
}

func getSource(oToken []string) (uint32, uint32, []string, bool) {
	token, tokens, ok := nextToken(oToken)
	if !ok {
		return 0, 0, oToken, false
	}

	switch token {
	case "any":
		return 0, 0, tokens, true
	case "host":
		token, tokens, ok = nextToken(tokens)
		if !ok {
			return 0, 0, oToken, false
		}

		hostIp, valid := parseIpv4(token)
		if valid {
			return hostIp, fullMask, tokens, true
		}

		return 0, 0, oToken, false
	}

	hostIp, valid := parseIpv4(token)
	if !valid {
		return 0, 0, oToken, false
	}

	token, tokens, ok = nextToken(tokens)
	if !ok {
		return 0, 0, oToken, false
	}

	hostMask, valid := parseIpv4(token)
	if valid {
		return hostIp, fullMask - hostMask, tokens, true
	}

	return 0, 0, oToken, false
}

func nextToken(tokens []string) (string, []string, bool) {
	if len(tokens) == 0 {
		return "", nil, false
	}

	return tokens[0], tokens[1:], true
}

func getPort(protocol int16, oTokens []string) (int, uint16, uint16, []string, bool) {
	token, tokens, ok := nextToken(oTokens)
	if !ok {
		return invalidOp, 0, 0, oTokens, false
	}

	op, found := validOps[token]
	if !found {
		return invalidOp, 0, 0, oTokens, false
	}

	port, tokens, ok := nextToken(tokens)
	if !ok {
		return invalidOp, 0, 0, oTokens, false
	}

	startPort, ok := lookupPort(protocol, port)
	endPort := startPort
	if !ok {
		return invalidOp, 0, 0, oTokens, false
	}

	if op == portOpRange {
		port, tokens, ok = nextToken(tokens)
		if !ok {
			return invalidOp, 0, 0, oTokens, false
		}

		endPort, ok = lookupPort(protocol, port)
		if !ok {
			return invalidOp, 0, 0, oTokens, false
		}
	}

	return op, startPort, endPort, tokens, true
}

func getIcmpRule(oTokens []string) (icmpRule, []string, bool) {
	rule := icmpRule{invalidIcmpTypeCode, invalidIcmpTypeCode}
	token, tokens, ok := nextToken(oTokens)
	if !ok {
		return rule, oTokens, false
	}

	if icmpType, found := icmpTypes[token]; found {
		rule.iType = int16(icmpType)
	} else {
		num, err := strconv.ParseUint(token, 10, 8)
		if err != nil {
			return rule, oTokens, false
		}

		rule.iType = int16(num)
	}

	oTokens = tokens
	token, tokens, ok = nextToken(tokens)
	if !ok {
		return rule, oTokens, true
	}

	num, err := strconv.ParseUint(token, 10, 8)
	if err != nil {
		return rule, oTokens, true
	}

	rule.code = int16(num)
	return rule, tokens, true
}

func lookupPort(protocol int16, port string) (uint16, bool) {
	num, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, false
	}

	return uint16(num), true
}

func parseIpv4(ip string) (uint32, bool) {
	a, i, ok := dtoi(ip)
	if !ok {
		return 0, false
	}

	ip = ip[i+1:]
	b, i, ok := dtoi(ip)
	if !ok {
		return 0, false
	}

	ip = ip[i+1:]
	c, i, ok := dtoi(ip)
	if !ok {
		return 0, false
	}

	ip = ip[i+1:]
	d, i, ok := dtoi(ip)
	if !ok {
		return 0, false
	}

	return toIpv4(byte(a), byte(b), byte(c), byte(d)), true
}

// Decimal to integer.
// Returns number, characters consumed, success.
func dtoi(s string) (n int, i int, ok bool) {
	n = 0
	for i = 0; i < len(s) && '0' <= s[i] && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n >= 256 {
			return 256, i, false
		}
	}

	if i == 0 {
		return 0, 0, false
	}

	return n, i, true
}

func twoPartAcl(tokens []string) RuleFunc {
	if tokens[1] == "any" {
		switch tokens[0] {
		case "permit":
			return RulePermit
		case "deny":
			return RuleDeny
		}
	}

	return nil
}
