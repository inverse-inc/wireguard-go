package test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestAuto(t *testing.T) {
	t.Parallel()
	tmpdir, err := ioutil.TempDir(os.TempDir(), "coredns")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	corefile := `org:0 {
		auto {
			directory ` + tmpdir + ` db\.(.*) {1}
			reload 0.1s
		}
	}`

	i, udp, _, err := CoreDNSServerAndPorts(corefile)
	if err != nil {
		t.Fatalf("Could not get CoreDNS serving instance: %s", err)
	}
	defer i.Stop()

	m := new(dns.Msg)
	m.SetQuestion("www.example.org.", dns.TypeA)
	resp, err := dns.Exchange(m, udp)
	if err != nil {
		t.Fatal("Expected to receive reply, but didn't")
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("Expected reply to be a SERVFAIL, got %d", resp.Rcode)
	}

	// Write db.example.org to get example.org.
	if err = ioutil.WriteFile(filepath.Join(tmpdir, "db.example.org"), []byte(zoneContent), 0644); err != nil {
		t.Fatal(err)
	}

	time.Sleep(150 * time.Millisecond) // wait for it to be picked up

	resp, err = dns.Exchange(m, udp)
	if err != nil {
		t.Fatal("Expected to receive reply, but didn't")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("Expected 1 RR in the answer section, got %d", len(resp.Answer))
	}

	// Remove db.example.org again.
	os.Remove(filepath.Join(tmpdir, "db.example.org"))

	time.Sleep(150 * time.Millisecond) // wait for it to be picked up
	resp, err = dns.Exchange(m, udp)
	if err != nil {
		t.Fatal("Expected to receive reply, but didn't")
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("Expected reply to be a SERVFAIL, got %d", resp.Rcode)
	}
}

func TestAutoNonExistentZone(t *testing.T) {
	t.Parallel()
	tmpdir, err := ioutil.TempDir(os.TempDir(), "coredns")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	corefile := `.:0 {
		auto {
			directory ` + tmpdir + ` (.*) {1}
			reload 1s
		}
		errors stdout
	}`

	i, err := CoreDNSServer(corefile)
	if err != nil {
		t.Fatalf("Could not get CoreDNS serving instance: %s", err)
	}

	udp, _ := CoreDNSServerPorts(i, 0)
	if udp == "" {
		t.Fatal("Could not get UDP listening port")
	}
	defer i.Stop()

	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	resp, err := dns.Exchange(m, udp)
	if err != nil {
		t.Fatal("Expected to receive reply, but didn't")
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("Expected reply to be a SERVFAIL, got %d", resp.Rcode)
	}
}

func TestAutoAXFR(t *testing.T) {
	t.Parallel()

	tmpdir, err := ioutil.TempDir(os.TempDir(), "coredns")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	corefile := `org:0 {
		auto {
			directory ` + tmpdir + ` db\.(.*) {1}
			reload 0.1s
		}
		transfer {
			to *
		}
	}`

	i, err := CoreDNSServer(corefile)
	if err != nil {
		t.Fatalf("Could not get CoreDNS serving instance: %s", err)
	}

	_, tcp := CoreDNSServerPorts(i, 0)
	if tcp == "" {
		t.Fatal("Could not get TCP listening port")
	}
	defer i.Stop()

	// Write db.example.org to get example.org.
	if err = ioutil.WriteFile(filepath.Join(tmpdir, "db.example.org"), []byte(zoneContent), 0644); err != nil {
		t.Fatal(err)
	}

	time.Sleep(150 * time.Millisecond) // wait for it to be picked up

	tr := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetAxfr("example.org.")
	c, err := tr.In(m, tcp)
	if err != nil {
		t.Fatal("Expected to receive reply, but didn't")
	}
	l := 0
	for e := range c {
		l += len(e.RR)
	}

	if l != 5 {
		t.Fatalf("Expected response with %d RRs, got %d", 5, l)
	}
}

const zoneContent = `; testzone
@   IN SOA sns.dns.icann.org. noc.dns.icann.org. 2016082534 7200 3600 1209600 3600
    IN NS  a.iana-servers.net.
    IN NS  b.iana-servers.net.

www IN A   127.0.0.1
`
