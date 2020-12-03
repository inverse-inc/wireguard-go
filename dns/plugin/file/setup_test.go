package file

import (
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/test"
)

func TestFileParse(t *testing.T) {
	zoneFileName1, rm, err := test.TempFile(".", dbMiekNL)
	if err != nil {
		t.Fatal(err)
	}
	defer rm()

	zoneFileName2, rm, err := test.TempFile(".", dbDnssexNLSigned)
	if err != nil {
		t.Fatal(err)
	}
	defer rm()

	tests := []struct {
		inputFileRules string
		shouldErr      bool
		expectedZones  Zones
	}{
		{
			`file ` + zoneFileName1 + ` miek.nl.`,
			false,
			Zones{Names: []string{"miek.nl."}},
		},
		{
			`file ` + zoneFileName2 + ` dnssex.nl.`,
			false,
			Zones{Names: []string{"dnssex.nl."}},
		},
		{
			`file ` + zoneFileName2 + ` 10.0.0.0/8`,
			false,
			Zones{Names: []string{"10.in-addr.arpa."}},
		},
		// errors.
		{
			`file ` + zoneFileName1 + ` miek.nl {
				transfer from 127.0.0.1
			}`,
			true,
			Zones{},
		},
		{
			`file`,
			true,
			Zones{},
		},
		{
			`file ` + zoneFileName1 + ` example.net. {
				no_reload
			}`,
			true,
			Zones{},
		},
		{
			`file ` + zoneFileName1 + ` example.net. {
				no_rebloat
			}`,
			true,
			Zones{},
		},
	}

	for i, test := range tests {
		c := caddy.NewTestController("dns", test.inputFileRules)
		actualZones, err := fileParse(c)

		if err == nil && test.shouldErr {
			t.Fatalf("Test %d expected errors, but got no error", i)
		} else if err != nil && !test.shouldErr {
			t.Fatalf("Test %d expected no errors, but got '%v'", i, err)
		} else {
			if len(actualZones.Names) != len(test.expectedZones.Names) {
				t.Fatalf("Test %d expected %v, got %v", i, test.expectedZones.Names, actualZones.Names)
			}
			for j, name := range test.expectedZones.Names {
				if actualZones.Names[j] != name {
					t.Fatalf("Test %d expected %v for %d th zone, got %v", i, name, j, actualZones.Names[j])
				}
			}
		}
	}
}

func TestParseReload(t *testing.T) {
	name, rm, err := test.TempFile(".", dbMiekNL)
	if err != nil {
		t.Fatal(err)
	}
	defer rm()

	tests := []struct {
		input  string
		reload time.Duration
	}{
		{
			`file ` + name + ` example.org.`,
			1 * time.Minute,
		},
		{
			`file ` + name + ` example.org. {
			reload 5s
			}`,
			5 * time.Second,
		},
	}

	for i, test := range tests {
		c := caddy.NewTestController("dns", test.input)
		z, _ := fileParse(c)
		if x := z.Z["example.org."].ReloadInterval; x != test.reload {
			t.Errorf("Test %d expected reload to be %s, but got %s", i, test.reload, x)
		}
	}
}
