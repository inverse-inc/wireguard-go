package filter

import (
	"fmt"
	"errors"
	"strconv"
	"strings"
)

const (
	ipv4Version     = byte(0x40)
	ipv6Version     = byte(0x60)
	tcpProtocol     = byte(6)
	udpProtocol     = byte(17)
	icmpProtocol    = byte(1)
	icmpEchoReply   = byte(0)
	icmpEchoRequest = byte(8)
)

var icmpTypes = map[string]byte{
	"echo-reply":           0,
	"source-quench":        4,
	"redirect":             5,
	"alternate-address":    6,
	"echo":                 8,
	"router-advertisement": 9,
	"router-solicitation":  10,
	"time-exceeded":        11,
	"parameter-problem":    12,
	"timestamp-request":    13,
	"timestamp-reply":      14,
	"information-request":  15,
	"information-reply":    16,
	"mask-request":         17,
	"mask-reply":           18,
	"traceroute":           30,
	"conversion-error":     31,
	"mobile-redirect":      32,
}

/*
map[string]byte{
	"administratively-prohibited": 256,
	"host-unknown":                256,
	"host-tos-unreachable":        256,
	"host-unreachable":            256,
	"net-tos-unreachable":         256,
	"net-unreachable":             256,
	"network-unknown":             256,
	"unreachable":                 256,
	"host-precedence-unreachable": 256,
	"dod-host-prohibited":         256,
	"dod-net-prohibited":          256,
	"dscp":                        256,
	"fragments":                   256,
	"general-parameter-problem":   256,
	"host-isolated":               256,
	"host-redirect":               256,
	"host-tos-redirect":           256,
	"log":                         256,
	"log-input":                   256,
	"net-redirect":                256,
	"net-tos-redirect":            256,
	"no-room-for-option":          256,
	"option":                      256,
	"option-missing":              256,
	"packet-too-big":              256,
	"port-unreachable":            256,
	"precedence":                  256,
	"precedence-unreachable":      256,
	"protocol-unreachable":        256,
	"reassembly-timeout":          256,
	"source-route-failed":         256,
	"time-range":                  256,
	"tos":                         256,
	"ttl":                         256,
	"ttl-exceeded":                256,
}
*/

type portMap map[uint16]struct{}
type icmpTypeMap map[byte]struct{}

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

func (m icmpTypeMap) IsAllowed(t uint8) bool {
	if m == nil {
		return true
	}

	_, found := m[t]
	return found
}

func (m icmpTypeMap) IsDenied(t uint8) bool {
	if m == nil {
		return false
	}

	_, found := m[t]
	return found
}

type PortFilter struct {
	AllowedDstTCPPorts portMap
	AllowedSrcTCPPorts portMap
	AllowedSrcUDPPorts portMap
	AllowedDstUDPPorts portMap
	AllowedICMPType    icmpTypeMap
	DenyDstTCPPorts    portMap
	DenySrcTCPPorts    portMap
	DenySrcUDPPorts    portMap
	DenyDstUDPPorts    portMap
	DenyICMPType       icmpTypeMap
	DenyICMP           bool
	DenyAll            bool
	AllowAll           bool
}

func NewPortFilter() *PortFilter {
	return &PortFilter{}
}

func (f *PortFilter) AddDenyICMPType(types []byte) {
	if f.DenyICMPType == nil {
		f.DenyICMPType = make(map[byte]struct{})
	}
	for _, t := range types {
		f.DenyICMPType[t] = struct{}{}
	}
}

func (f *PortFilter) AddAllowedICMPType(types []byte) {
	if f.AllowedICMPType == nil {
		f.AllowedICMPType = make(map[byte]struct{})
	}
	for _, t := range types {
		f.AllowedICMPType[t] = struct{}{}
	}
}

func (f *PortFilter) Pass(p []byte) error {
	if len(p) == 0 {
		return nil
	}

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
				return errors.New("TCP DST port denied")
			}

			if f.DenySrcTCPPorts.IsDenied(srcPort) {
				return errors.New("TCP SRC port denied")
			}

			return nil
		case icmpProtocol:
			if f.DenyICMP {
				return errors.New("ICMP denied")
			}

			icmpType := data[0]
			if !f.AllowedICMPType.IsAllowed(icmpType) {
				return errors.New("ICMP type not allowed")
			}

			if f.DenyICMPType.IsDenied(icmpType) {
				return errors.New("ICMP type denied")
			}

			return nil
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
			if len(parts) != 5 {
				return
			}

			if icmpType, found := icmpTypes[parts[4]]; found {
				f.AddAllowedICMPType([]byte{icmpType})
			}

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
			if len(parts) != 5 {
				return
			}

			if icmpType, found := icmpTypes[parts[4]]; found {
				f.AddDenyICMPType([]byte{icmpType})
			}
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
