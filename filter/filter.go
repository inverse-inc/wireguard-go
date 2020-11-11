package filter

import (
	"errors"
	"strconv"
	"strings"
)

const ipv4Version = byte(0x40)
const ipv6Version = byte(0x60)
const tcpProtocol = byte(6)
const udpProtocol = byte(17)
const icmpProtocol = byte(1)

type portMap map[uint16]struct{}

func (m portMap) IsAllowed(port uint16) bool {
	if m == nil {
		return true
	}

	_, found := m[port]
	return found
}

func (m portMap) IsDenied(port uint16) bool {
	if m == nil {
		return false
	}

	_, found := m[port]
	return found
}

type PortFilter struct {
	AllowedDstTCPPorts portMap
	AllowedSrcTCPPorts portMap
	AllowedSrcUDPPorts portMap
	AllowedDstUDPPorts portMap
	DenyDstTCPPorts    portMap
	DenySrcTCPPorts    portMap
	DenySrcUDPPorts    portMap
	DenyDstUDPPorts    portMap
	DenyICMP           bool
	DenyAll            bool
	AllowAll           bool
}

func NewPortFilter() *PortFilter {
	return &PortFilter{}
}

func (f *PortFilter) Pass(p []byte) error {
	if f.DenyAll {
		return errors.New("Deny All")
	}

	if f.AllowAll {
		return nil
	}

	version := p[0] & 0xF0
	switch version {
	default:
		return nil
	case ipv4Version:
		hlength := (p[0] & 0x0F) << 2
		protocol := p[9]
		data := p[hlength:]
		switch protocol {
		default:
			return nil
		case udpProtocol:
			srcPort := ((uint16(data[0]) << 8) | uint16(data[1]))
			dstPort := ((uint16(data[2]) << 8) | uint16(data[3]))
			if !f.AllowedDstUDPPorts.IsAllowed(dstPort) {
				return errors.New("UDP DST port not allowed")
			}

			if !f.AllowedSrcUDPPorts.IsAllowed(srcPort) {
				return errors.New("UDP SRC port not allowed")
			}

			if f.DenyDstUDPPorts.IsDenied(dstPort) {
				return errors.New("UDP DST port not denied")
			}

			if f.DenySrcUDPPorts.IsDenied(srcPort) {
				return errors.New("UDP SRC port not denied")
			}

			return nil
		case tcpProtocol:
			srcPort := ((uint16(data[0]) << 8) | uint16(data[1]))
			dstPort := ((uint16(data[2]) << 8) | uint16(data[3]))
			if !f.AllowedDstTCPPorts.IsAllowed(dstPort) {
				return errors.New("TCP DST port not allowed")
			}

			if !f.AllowedSrcTCPPorts.IsAllowed(srcPort) {
				return errors.New("TCP SRC port not allowed")
			}

			if f.DenyDstTCPPorts.IsDenied(dstPort) {
				return errors.New("TCP DST port not denied")
			}

			if f.DenySrcTCPPorts.IsDenied(srcPort) {
				return errors.New("TCP SRC port not denied")
			}

			return nil
		case icmpProtocol:
			if f.DenyICMP {
				return errors.New("ICMP denied")
			}
		}
	case ipv6Version:
		return errors.New("Not Allowed")
	}

	return nil
}

func checkAllowedDstSrcPorts(dstMap, srcMap portMap, dstPort, srcPort uint16) error {
	return nil
}

func updatePortMap(m *portMap, ports []uint16) {
	if *m == nil {
		*m = make(map[uint16]struct{})
	}

	for _, port := range ports {
		(*m)[port] = struct{}{}
	}
}

func True([]byte) error {
	return nil
}

func (f *PortFilter) AddAllowedDstTcpPorts(ports []uint16) {
	updatePortMap(&f.AllowedDstTCPPorts, ports)
}

func (f *PortFilter) AddAllowedSrcTcpPorts(ports []uint16) {
	updatePortMap(&f.AllowedSrcTCPPorts, ports)
}

func (f *PortFilter) AddAllowedDstUdpPorts(ports []uint16) {
	updatePortMap(&f.AllowedDstUDPPorts, ports)
}

func (f *PortFilter) AddAllowedSrcUdpPorts(ports []uint16) {
	updatePortMap(&f.AllowedSrcUDPPorts, ports)
}

func (f *PortFilter) AddDenyDstTcpPorts(ports []uint16) {
	updatePortMap(&f.DenyDstTCPPorts, ports)
}

func (f *PortFilter) AddDenySrcTcpPorts(ports []uint16) {
	updatePortMap(&f.DenySrcTCPPorts, ports)
}

func (f *PortFilter) AddDenyDstUdpPorts(ports []uint16) {
	updatePortMap(&f.DenyDstUDPPorts, ports)
}

func (f *PortFilter) AddDenySrcUdpPorts(ports []uint16) {
	updatePortMap(&f.DenySrcUDPPorts, ports)
}

func (f *PortFilter) AddACL(acl string) {
	parts := strings.Fields(acl)
	if len(parts) < 5 || len(parts) > 6 {
		return
	}

	switch parts[0] {
	default:
		return
	case "permit":
		switch parts[1] {
		default:
			return
		case "tcp":
			if len(parts) != 6 {
				return
			}
			if s, err := strconv.ParseUint(parts[5], 10, 16); err == nil {
				f.AddAllowedDstTcpPorts([]uint16{uint16(s)})
			}
		case "udp":
			if len(parts) != 6 {
				return
			}
			if s, err := strconv.ParseUint(parts[5], 10, 16); err == nil {
				f.AddAllowedDstUdpPorts([]uint16{uint16(s)})
			}
		case "icmp":
		}
	case "deny":
		switch parts[1] {
		default:
			return
		case "tcp":
			if len(parts) != 6 {
				return
			}
			if s, err := strconv.ParseUint(parts[5], 10, 16); err == nil {
				f.AddDenyDstTcpPorts([]uint16{uint16(s)})
			}
		case "udp":
			if len(parts) != 6 {
				return
			}
			if s, err := strconv.ParseUint(parts[5], 10, 16); err == nil {
				f.AddDenyDstUdpPorts([]uint16{uint16(s)})
			}
		case "icmp":
		}
	}
}

func NewFilterFromAcls(acls []string) func([]byte) error {
	filter := &PortFilter{}
	if len(acls) == 0 {
		filter.AllowAll = true
		return filter.Pass
	} else {
		for _, acl := range acls {
			filter.AddACL(acl)
		}
	}

	return filter.Pass
}
