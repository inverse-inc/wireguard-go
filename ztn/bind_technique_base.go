package ztn

import (
	"crypto/rand"

	"github.com/inverse-inc/packetfence/go/sharedutils"
)

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
