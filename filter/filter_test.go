package filter

import (
	"testing"
)

var packets = [][]byte{
	[]byte{69, 0, 0, 60, 203, 131, 64, 0, 64, 6, 99, 226, 192, 168, 69, 3, 192, 168, 69, 2, 153, 222, 17, 92, 31, 232, 147, 213, 0, 0, 0, 0, 160, 2, 107, 208, 25, 66, 0, 0, 2, 4, 5, 100, 4, 2, 8, 10, 0, 153, 88, 86, 0, 0, 0, 0, 1, 3, 3, 7},
	[]byte{69, 0, 0, 52, 203, 132, 64, 0, 64, 6, 99, 233, 192, 168, 69, 3, 192, 168, 69, 2, 153, 222, 17, 92, 31, 232, 147, 214, 181, 110, 17, 81, 128, 16, 0, 216, 252, 127, 0, 0, 1, 1, 8, 10, 0, 153, 88, 88, 0, 151, 238, 205},
	[]byte{69, 0, 0, 58, 203, 133, 64, 0, 64, 6, 99, 226, 192, 168, 69, 3, 192, 168, 69, 2, 153, 222, 17, 92, 31, 232, 147, 214, 181, 110, 17, 81, 128, 24, 0, 216, 184, 149, 0, 0, 1, 1, 8, 10, 0, 153, 88, 88, 0, 151, 238, 205, 104, 101, 108, 108, 111, 10},
	[]byte{69, 0, 0, 52, 203, 134, 64, 0, 64, 6, 99, 231, 192, 168, 69, 3, 192, 168, 69, 2, 153, 222, 17, 92, 31, 232, 147, 220, 181, 110, 17, 81, 128, 17, 0, 216, 252, 120, 0, 0, 1, 1, 8, 10, 0, 153, 88, 88, 0, 151, 238, 205},
	[]byte{69, 0, 0, 52, 203, 135, 64, 0, 64, 6, 99, 230, 192, 168, 69, 3, 192, 168, 69, 2, 153, 222, 17, 92, 31, 232, 147, 221, 181, 110, 17, 82, 128, 16, 0, 216, 252, 110, 0, 0, 1, 1, 8, 10, 0, 153, 88, 93, 0, 151, 238, 209},
}

var udpPacket = []byte{69, 0, 0, 34, 51, 79, 64, 0, 64, 17, 252, 37, 192, 168, 69, 3, 192, 168, 69, 2, 141, 66, 17, 92, 0, 14, 18, 1, 104, 101, 108, 108, 111, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
var icmpPacket = []byte{0x45, 0x00, 0x00, 0x54, 0x26, 0xef, 0x00, 0x00, 0x40, 0x01, 0x57, 0xf9, 0xc0, 0xa8, 0x2b, 0x09, 0x08, 0x08, 0x08, 0x08, 0x08, 0x00, 0xbb, 0xb3, 0xd7, 0x3b, 0x00, 0x00, 0x51, 0xa7, 0xd6, 0x7d, 0x00, 0x04, 0x51, 0xe4, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37}

func TestIpv4PortAllowFilter(t *testing.T) {
	filter := NewPortFilter()
	filter.AddAllowedDstTcpPorts([]uint16{4444})
	runPassingFilters(t, packets, filter)
	runPassingFilterFunc(t, packets, filter.Pass)

	filter = NewPortFilter()
	filter.AddAllowedDstTcpPorts([]uint16{4444, 4445})
	runPassingFilters(t, packets, filter)

	filter = NewPortFilter()
	filter.AddAllowedSrcTcpPorts([]uint16{39390})
	runPassingFilters(t, packets, filter)

	filter = NewPortFilter()
	filter.AddAllowedDstTcpPorts([]uint16{4445})
	runFailingFilters(t, packets, filter)

	filter = NewPortFilter()
	filter.AddAllowedSrcTcpPorts([]uint16{39391})
	runFailingFilters(t, packets, filter)

	filter = NewPortFilter()
	filter.AddAllowedDstUdpPorts([]uint16{4444})
	if err := filter.Pass(udpPacket); err != nil {
		t.Errorf("UDP Filter failed %s ", err.Error())
	}

}

func TestPortFilterFromAcl(t *testing.T) {
	filter := NewFilterFromAcls([]string{})
	runPassingFilterFunc(t, packets, filter)

	filter = NewFilterFromAcls([]string{"permit tcp any any eq 4444"})
	runPassingFilterFunc(t, packets, filter)

	filter = NewFilterFromAcls([]string{"deny tcp any any eq 4444"})
	runFailingFilterFunc(t, packets, filter)

	filter = NewFilterFromAcls([]string{"permit udp any any eq 4444"})
	runPassingFilterFunc(t, [][]byte{udpPacket}, filter)

	filter = NewFilterFromAcls([]string{"deny icmp any any echo"})
	runFailingFilterFunc(t, [][]byte{icmpPacket}, filter)

}

func TestIpv4PortFilterDeny(t *testing.T) {
	filter := NewPortFilter()
	filter.AddDenySrcTcpPorts([]uint16{39391})
	runPassingFilters(t, packets, filter)

	filter = NewPortFilter()
	filter.AddDenySrcTcpPorts([]uint16{39390})
	runFailingFilters(t, packets, filter)

	filter = NewPortFilter()
	filter.AddDenyDstTcpPorts([]uint16{4444})
	runFailingFilters(t, packets, filter)

	filter = NewPortFilter()
	filter.AddDenyDstTcpPorts([]uint16{4445})
	runPassingFilters(t, packets, filter)
}

func TestIcmp(t *testing.T) {
	filter := NewPortFilter()
	filter.AddDenyICMPType([]byte{icmpEchoRequest})
	runFailingFilters(t, [][]byte{icmpPacket}, filter)

}

func runPassingFilters(t *testing.T, packets [][]byte, filter *PortFilter) {
	for i, p := range packets {
		if err := filter.Pass(p); err != nil {
			t.Errorf("Filter failed %s for packet (%d)", err.Error(), i)
		}
	}
}

func runPassingFilterFunc(t *testing.T, packets [][]byte, pass func([]byte) error) {
	for i, p := range packets {
		if err := pass(p); err != nil {
			t.Errorf("Filter failed %s for packet (%d)", err.Error(), i)
		}
	}
}

func runFailingFilters(t *testing.T, packets [][]byte, filter *PortFilter) {
	for i, p := range packets {
		if err := filter.Pass(p); err == nil {
			t.Errorf("Filter passed for packet (%d) should have failed", i)
		}
	}
}

func runFailingFilterFunc(t *testing.T, packets [][]byte, pass func([]byte) error) {
	for i, p := range packets {
		if err := pass(p); err == nil {
			t.Errorf("Filter passed for packet (%d) should have failed", i)
		}
	}
}
