package ztn

import (
	"crypto/rand"

	"github.com/inverse-inc/packetfence/go/sharedutils"
)

type BindTechniqueMsg struct {
	id []byte
}

func (btm *BindTechniqueMsg) InitID() {
	btm.id = make([]byte, 64)
	_, err := rand.Read(btm.id)
	sharedutils.CheckError(err)
}

func (btm *BindTechniqueMsg) IsMessage(b []byte) bool {
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

func (btm *BindTechniqueMsg) AddIDToPacket(buf []byte) {
	for i, v := range btm.id {
		buf[i] = v
	}
}
