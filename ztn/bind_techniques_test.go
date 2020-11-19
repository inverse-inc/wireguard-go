package ztn

import "testing"

func TestBindTechniques(t *testing.T) {
	// Should default to STUN when empty
	if BindTechniques.Next() != BindSTUN {
		t.Error("Invalid default bind technique")
	}

	BindTechniques.Add(BindSTUN)
	BindTechniques.Add(BindUPNPGID)

	if BindTechniques.Next() != BindUPNPGID {
		t.Error("Invalid bind technique")
	}

	if BindTechniques.Next() != BindSTUN {
		t.Error("Invalid bind technique")
	}
}
