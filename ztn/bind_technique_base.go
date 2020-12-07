package ztn

import (
	"crypto/rand"
	"encoding/binary"
	"net"

	"github.com/inverse-inc/packetfence/go/sharedutils"
)

type BindTechniqueInterface interface {
	ParseBindRequestPkt([]byte) (net.IP, int, error)
}

type BindTechniqueBase struct {
	id     []byte
	inited bool
}

func (btm *BindTechniqueBase) InitID() {
	btm.id = make([]byte, 64)
	_, err := rand.Read(btm.id)
	btm.inited = true
	sharedutils.CheckError(err)
}

func (btm *BindTechniqueBase) IsMessage(b []byte) bool {
	if !btm.inited {
		panic("BindTechniqueBase ID uninitilized")
	}

	if len(b) < len(btm.id) {
		return false
	}

	for i := 0; i < len(btm.id); i++ {
		if b[i] != btm.id[i] {
			return false
		}
	}

	return true
}

func (btm *BindTechniqueBase) AddIDToPacket(buf []byte) {
	for i, v := range btm.id {
		buf[i] = v
	}
}

func (btm *BindTechniqueBase) BindRequestPkt(externalIP net.IP, externalPort int) []byte {
	var buf = defaultBufferPool.Get()
	btm.AddIDToPacket(buf)
	buf[len(btm.id)+1] = externalIP[12]
	buf[len(btm.id)+2] = externalIP[13]
	buf[len(btm.id)+3] = externalIP[14]
	buf[len(btm.id)+4] = externalIP[15]
	binary.PutUvarint(buf[len(btm.id)+5:], uint64(externalPort))
	return buf
}

func (btb *BindTechniqueBase) ParseBindRequestPkt(buf []byte) (net.IP, int, error) {
	ip := net.IPv4(buf[len(btb.id)+1], buf[len(btb.id)+2], buf[len(btb.id)+3], buf[len(btb.id)+4])
	port, _ := binary.Uvarint(buf[len(btb.id)+5:])
	return ip, int(port), nil
}
