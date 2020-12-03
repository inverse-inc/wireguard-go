package test

import (
	"testing"

	"github.com/inverse-inc/wireguard-go/dns/plugin/test"

	"github.com/miekg/dns"
)

func TestLookupProxy(t *testing.T) {
	t.Parallel()
	name, rm, err := test.TempFile(".", exampleOrg)
	if err != nil {
		t.Fatalf("Failed to create zone: %s", err)
	}
	defer rm()

	corefile := `example.org:0 {
		file ` + name + `
	}`

	i, udp, _, err := CoreDNSServerAndPorts(corefile)
	if err != nil {
		t.Fatalf("Could not get CoreDNS serving instance: %s", err)
	}
	defer i.Stop()

	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	resp, err := dns.Exchange(m, udp)
	if err != nil {
		t.Fatal("Expected to receive reply, but didn't")
	}
	// expect answer section with A record in it
	if len(resp.Answer) == 0 {
		t.Fatalf("Expected to at least one RR in the answer section, got none: %s", resp)
	}
	if resp.Answer[0].Header().Rrtype != dns.TypeA {
		t.Errorf("Expected RR to A, got: %d", resp.Answer[0].Header().Rrtype)
	}
	if resp.Answer[0].(*dns.A).A.String() != "127.0.0.1" {
		t.Errorf("Expected 127.0.0.1, got: %s", resp.Answer[0].(*dns.A).A.String())
	}
}

func BenchmarkProxyLookup(b *testing.B) {
	t := new(testing.T)
	name, rm, err := test.TempFile(".", exampleOrg)
	if err != nil {
		t.Fatalf("Failed to created zone: %s", err)
	}
	defer rm()

	corefile := `example.org:0 {
		file ` + name + `
	}`

	i, err := CoreDNSServer(corefile)
	if err != nil {
		t.Fatalf("Could not get CoreDNS serving instance: %s", err)
	}

	udp, _ := CoreDNSServerPorts(i, 0)
	if udp == "" {
		t.Fatalf("Could not get udp listening port")
	}
	defer i.Stop()

	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := dns.Exchange(m, udp); err != nil {
			b.Fatal("Expected to receive reply, but didn't")
		}
	}
}
