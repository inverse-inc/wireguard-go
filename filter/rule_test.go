package filter

import (
	"github.com/inverse-inc/wireguard-go/device"
	"testing"
)

var logger = device.NewLogger(
	device.LogLevelSilent,
	"(Testing)",
)

var rulePackets = [][]byte{
	[]byte{69, 0, 0, 60, 203, 131, 64, 0, 64, 6, 99, 226, 192, 168, 69, 3, 192, 168, 68, 2, 153, 222, 17, 92, 31, 232, 147, 213, 0, 0, 0, 0, 160, 2, 107, 208, 25, 66, 0, 0, 2, 4, 5, 100, 4, 2, 8, 10, 0, 153, 88, 86, 0, 0, 0, 0, 1, 3, 3, 7},
	[]byte{69, 0, 0, 52, 203, 132, 64, 0, 64, 6, 99, 233, 192, 168, 69, 3, 192, 168, 69, 2, 153, 222, 17, 92, 31, 232, 147, 214, 181, 110, 17, 81, 128, 16, 0, 216, 252, 127, 0, 0, 1, 1, 8, 10, 0, 153, 88, 88, 0, 151, 238, 205},
	[]byte{69, 0, 0, 58, 203, 133, 64, 0, 64, 6, 99, 226, 192, 168, 69, 3, 192, 168, 69, 2, 153, 222, 17, 92, 31, 232, 147, 214, 181, 110, 17, 81, 128, 24, 0, 216, 184, 149, 0, 0, 1, 1, 8, 10, 0, 153, 88, 88, 0, 151, 238, 205, 104, 101, 108, 108, 111, 10},
	[]byte{69, 0, 0, 52, 203, 134, 64, 0, 64, 6, 99, 231, 192, 168, 69, 3, 192, 168, 69, 2, 153, 222, 17, 92, 31, 232, 147, 220, 181, 110, 17, 81, 128, 17, 0, 216, 252, 120, 0, 0, 1, 1, 8, 10, 0, 153, 88, 88, 0, 151, 238, 205},
	[]byte{69, 0, 0, 52, 203, 135, 64, 0, 64, 6, 99, 230, 192, 168, 69, 3, 192, 168, 69, 2, 153, 222, 17, 92, 31, 232, 147, 221, 181, 110, 17, 82, 128, 16, 0, 216, 252, 110, 0, 0, 1, 1, 8, 10, 0, 153, 88, 93, 0, 151, 238, 209},
}

var udpRulePacket = []byte{69, 0, 0, 34, 51, 79, 64, 0, 64, 17, 252, 37, 192, 168, 69, 3, 192, 168, 69, 2, 141, 66, 17, 92, 0, 14, 18, 1, 104, 101, 108, 108, 111, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
var icmpRulePacket = []byte{0x45, 0x00, 0x00, 0x54, 0x26, 0xef, 0x00, 0x00, 0x40, 0x01, 0x57, 0xf9, 0xc0, 0xa8, 0x2b, 0x09, 0x08, 0x08, 0x08, 0x08, 0x08, 0x00, 0xbb, 0xb3, 0xd7, 0x3b, 0x00, 0x00, 0x51, 0xa7, 0xd6, 0x7d, 0x00, 0x04, 0x51, 0xe4, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37}

func TestPermitAllRule(t *testing.T) {
	rule := PermitAllRule()
	if rule(rulePackets[0]) != Permit {
		t.Error("The PermitAllRule failed tcp")
	}

	if rule(udpRulePacket) != Permit {
		t.Error("The PermitAllRule failed udp")
	}

	if rule(icmpRulePacket) != Permit {
		t.Error("The PermitAllRule failed icmp")
	}

}

func TestPermitAllProtoRule(t *testing.T) {
	rule := PermitAllTcpRule()
	if rule(rulePackets[0]) != Permit {
		t.Error("The PermitAllRule failed tcp")
	}

	if rule(udpRulePacket) != Skip {
		t.Error("The PermitAllRule did't skip udp")
	}

	if rule(icmpRulePacket) != Skip {
		t.Error("The PermitAllTcpRule did't skip icmp")
	}

	rule = PermitAllUdpRule()
	if rule(rulePackets[0]) != Skip {
		t.Error("The PermitAllUdpRule did't skip tcp")
	}

	if rule(udpRulePacket) != Permit {
		t.Error("The PermitAllUdpRule failed udp")
	}

	if rule(icmpRulePacket) != Skip {
		t.Error("The PermitAllTcpRule did't skip icmp")
	}

	rule = PermitAllIcmpRule()
	if rule(rulePackets[0]) != Skip {
		t.Error("The PermitAllUdpRule did't skip tcp")
	}

	if rule(udpRulePacket) != Skip {
		t.Error("The PermitAllUdpRule did't skip udp")
	}

	if rule(icmpRulePacket) != Permit {
		t.Error("The PermitAllTcpRule failed icmp")
	}

}

func TestDenyAllRule(t *testing.T) {
	rule := DenyAllRule()
	if rule(rulePackets[0]) != Deny {
		t.Error("The DenyAllRule failed tcp")
	}

	if rule(udpRulePacket) != Deny {
		t.Error("The DenyAllRule failed udp")
	}

	if rule(icmpRulePacket) != Deny {
		t.Error("The DenyAllRule failed icmp")
	}
}

func TestIpv4NetworkMask(t *testing.T) {
	nm := Ipv4NetworkMask{toIpv4(192, 168, 2, 0), toIpv4(255, 255, 255, 0)}
	if !nm.Match(toIpv4(192, 168, 2, 1)) {
		t.Error("192,168,2,1 failed to match 192,168,2,0/255,255,255,0")
	}

	if nm.Match(toIpv4(192, 168, 3, 1)) {
		t.Error("192,168,3,1 match 192,168,2,0/255,255,255,0")
	}
}

func TestPermitSrcIpRule(t *testing.T) {
	rule := PermitSrcIpRule(toIpv4(192, 168, 69, 0), toIpv4(255, 255, 255, 0))
	if rule(rulePackets[0]) != Permit {
		t.Error("Packet was not permited")
	}
}

func TestDenySrcIpRule(t *testing.T) {
	rule := DenySrcIpRule(toIpv4(192, 168, 69, 0), toIpv4(255, 255, 255, 0))
	if rule(rulePackets[0]) != Deny {
		t.Error("Packet was not denied")
	}
}

func TestDenyDstIpRule(t *testing.T) {
	rule := DenyDstIpRule(toIpv4(192, 168, 68, 0), toIpv4(255, 255, 255, 0))
	if rule(rulePackets[0]) != Deny {
		t.Error("Packet was not denied")
	}
}

func TestPermitDstIpRule(t *testing.T) {
	rule := PermitDstIpRule(toIpv4(192, 168, 68, 0), toIpv4(255, 255, 255, 0))
	if rule(rulePackets[0]) != Permit {
		t.Error("Packet was not permited")
	}
}

func TestPermitAny(t *testing.T) {
	rules := AclsToRules(logger, "permit any")
	if !rules.PassDefaultDeny(rulePackets[0]) {
		t.Error("permit any failed")
	}

	rules = AclsToRules(logger, "permit 0.0.0.0 255.255.255.255")
	if !rules.PassDefaultDeny(rulePackets[0]) {
		t.Error("permit any failed")
	}
}

func TestPermitHost(t *testing.T) {
	rules := AclsToRules(logger, "permit host 192.168.69.3")
	if !rules.PassDefaultDeny(rulePackets[0]) {
		t.Error("permit host 192.169.68.3 failed")
	}
}

func TestDenyAny(t *testing.T) {
	rules := AclsToRules(logger, "deny any")
	if rules.PassDefaultPermit(rulePackets[0]) {
		t.Error("deny any failed")
	}
}

func TestPermitSrcDstPortProto(t *testing.T) {
	rules := AclsToRules(logger, "permit tcp any any eq 80")
	if rules.PassDefaultDeny(rulePackets[0]) {
		t.Error("permit tcp any any eq 80 failed")
	}
}

func TestSimpleHost(t *testing.T) {
	acls := []string{
		"permit host 192.168.69.3",
		"permit 192.168.69.3 0.0.0.0",
		"permit ip 192.168.69.3 0.0.0.0 any",
	}

	for _, acl := range acls {
		rules := AclsToRules(logger, acl)
		if !rules.PassDefaultDeny(rulePackets[0]) {
			t.Errorf("acl '%s' failed", acl)
		}
	}
}

func TestIcmpPermitAny(t *testing.T) {
	acls := []string{
		"permit icmp any any",
	}

	for _, acl := range acls {
		rules := AclsToRules(logger, acl)
		if !rules.PassDefaultDeny(icmpPacket1) {
			t.Errorf("acl '%s' failed", acl)
		}

		if rules.PassDefaultDeny(rulePackets[0]) {
			t.Errorf("acl '%s' passed", acl)
		}
	}
}

func TestIcmpPermit(t *testing.T) {
	acls := []string{
		"permit icmp any any echo",
		"permit icmp any any echo 0",
	}

	for _, acl := range acls {
		rules := AclsToRules(logger, acl)
		if !rules.PassDefaultDeny(icmpPacket1) {
			t.Errorf("acl '%s' failed", acl)
		}

	}

	for _, acl := range acls {
		rules := AclsToRules(logger, acl)
		if rules.PassDefaultDeny(icmpPacket2) {
			t.Errorf("acl '%s' passed", acl)
		}

	}
}

func TestIcmpDeny(t *testing.T) {
	acls := []string{
		"deny icmp any any echo",
		"deny icmp any any echo 0",
	}

	for _, acl := range acls {
		rules := AclsToRules(logger, acl)
		if rules.PassDefaultDeny(icmpPacket1) {
			t.Errorf("acl '%s' passed", acl)
		}

	}

	for _, acl := range acls {
		rules := AclsToRules(logger, acl)
		if !rules.PassDefaultPermit(icmpPacket2) {
			t.Errorf("acl '%s' deny", acl)
		}

	}
}
