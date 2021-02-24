package filter

import (
	"strings"
	"testing"
)

func TestParseIpv4(t *testing.T) {
	ip, valid := parseIpv4("1.2.3.4")
	if !valid {
		t.Error("parseIpv4 says 1.2.3.4 is invalid")
	} else {
		if ip != toIpv4(1, 2, 3, 4) {
			t.Error("parseIpv4 did not parse 1.2.3.4 properly")
		}
	}

	ip, valid = parseIpv4("0.0.0.0")
	if !valid {
		t.Error("parseIpv4 says 0.0.0.0 is invalid")
	} else {
		if ip != toIpv4(0, 0, 0, 0) {
			t.Error("parseIpv4 did not parse 0.0.0.0 properly")
		}
	}

}

func TestGetSource(t *testing.T) {
	net, mask, tokens, ok := getSource([]string{"host", "192.168.69.3"})
	if !ok {
		t.Fatal("getSource failed")
	}

	if net != toIpv4(192, 168, 69, 3) {
		t.Fatal("getSource network is invalid")
	}

	if mask != toIpv4(255, 255, 255, 255) {
		t.Fatal("getSource mask is invalid")
	}

	if len(tokens) != 0 {
		t.Fatal("getSource tokens is invalid")
	}

}

func TestGetProtocol(t *testing.T) {
	protocol, tokens, ok := getProtocol([]string{"ip", "any", "any"})
	if !ok {
		t.Fatal("getProtocol failed")
	}

	if protocol != allProtocols {
		t.Fatal("getProtocol did not parse protocol")
	}

	if len(tokens) != 2 {
		t.Fatal("getProtocol did not parse tokens")
	}

	protocol, tokens, ok = getProtocol([]string{"54", "any", "any"})
	if !ok {
		t.Fatal("getProtocol failed")
	}

	if protocol != 54 {
		t.Fatal("getProtocol did not parse protocol")
	}

	if len(tokens) != 2 {
		t.Fatal("getProtocol did not parse tokens")
	}

}

type getPortExpected struct {
	op        int
	tokens    []string
	startPort uint16
	endPort   uint16
	ok        bool
}

func TestGetPort(t *testing.T) {
	tests := []struct {
		protocol int16
		input    string
		expected getPortExpected
	}{
		{6, "eq 123 any", getPortExpected{portOpEq, []string{"any"}, 123, 123, true}},
		{6, "neq 123 any", getPortExpected{portOpNeq, []string{"any"}, 123, 123, true}},
		{6, "gt 123 any", getPortExpected{portOpGt, []string{"any"}, 123, 123, true}},
		{6, "lt 123 any", getPortExpected{portOpLt, []string{"any"}, 123, 123, true}},
		{6, "range 123 125 any", getPortExpected{portOpRange, []string{"any"}, 123, 125, true}},
		{6, "range 123 any", getPortExpected{invalidOp, []string{"range", "123", "any"}, 0, 0, false}},
		{6, "eq any", getPortExpected{invalidOp, []string{"eq", "any"}, 0, 0, false}},
	}

	for _, test := range tests {
		op, startPort, endPort, tokens, ok := getPort(test.protocol, strings.Fields(test.input))
		e := test.expected

		if ok != e.ok {
			t.Fatalf("Expected value for ok failed for '%s'", test.input)
		}

		if op != e.op {
			t.Fatalf("Expected value for op failed for '%s' expected '%d' got '%d'", test.input, e.op, op)
		}

		if startPort != e.startPort {
			t.Fatalf("Expected value for startPort failed for '%s' expected '%d' got '%d'", test.input, e.startPort, startPort)
		}

		if endPort != e.endPort {
			t.Fatalf("Expected value for endPort failed for '%s' expected '%d' got '%d'", test.input, e.endPort, endPort)
		}

		if len(tokens) != len(e.tokens) {
			t.Fatalf("Expected value for tokens failed for '%s' expected '%d' got '%d'", test.input, len(e.tokens), len(tokens))
		}

	}

}

func TestGetIcmpRule(t *testing.T) {
	tests := []struct {
		acl    string
		rule   icmpRule
		tokens []string
		ok     bool
	}{
		{"echo", icmpRule{8, -1}, []string{}, true},
		{"echo 5", icmpRule{8, 5}, []string{}, true},
		{"bob", icmpRule{-1, -1}, []string{"bob"}, false},
		{"echo bob", icmpRule{8, -1}, []string{"bob"}, true},
	}
	for _, test := range tests {
		acl := test.acl
		icmpRule, tokens, ok := getIcmpRule(strings.Fields(acl))
		if ok != test.ok {
			t.Fatalf("Expected value for ok failed for '%s'", acl)
		}

		if icmpRule.iType != test.rule.iType {
			t.Fatalf("Expected value for iType failed for '%s' expected '%d' got '%d'", acl, test.rule.iType, icmpRule.iType)
		}

		if icmpRule.code != test.rule.code {
			t.Fatalf("Expected value for code failed for '%s' expected '%d' got '%d'", acl, test.rule.code, icmpRule.code)
		}

		if len(tokens) != len(test.tokens) {
			t.Fatalf("Expected value for len tokens failed for '%s' expected '%d' got '%d'", acl, len(test.tokens), len(tokens))
		}
	}
}
