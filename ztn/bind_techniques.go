package ztn

import (
	"sort"
	"sync"
)

type BindTechnique string

func (bt BindTechnique) Priority() int {
	if p, ok := bindTechniquePriorities[bt]; ok {
		return p
	} else {
		panic("Priority for " + string(bt) + " not found")
	}
}

func (bt BindTechnique) Weight() int {
	return 100 - bt.Priority()
}

var bindTechniquePriorities = map[BindTechnique]int{
	BindDirectPublic: 11,
	BindUPNPIGD:      21,
	BindSTUN:         31,
	BindNATPMP:       41,
	BindThroughPeer:  51,
}

var BindTechniqueNames = map[string]BindTechnique{
	"STUN":         BindSTUN,
	"UPNPIGD":      BindUPNPIGD,
	"NATPMP":       BindNATPMP,
	"THROUGH_PEER": BindThroughPeer,
}

const (
	// These will get ordered in the BindTechniques.
	// Lower string == tried first if available
	// NAT PMP hasn't worked well in a few places so its left to be tried last
	BindAutomatic    = BindTechnique("AUTOMATIC")
	BindDirectPublic = BindTechnique("DIRECT_PUBLIC")
	BindNATPMP       = BindTechnique("NATPMP")
	BindSTUN         = BindTechnique("STUN")
	BindThroughPeer  = BindTechnique("THROUGH_PEER")
	BindUPNPIGD      = BindTechnique("UPNPIGD")
)

var DefaultBindTechnique = BindSTUN

type BindTechniquesStruct struct {
	sync.Mutex
	bindTechniques map[BindTechnique]bool
	sorted         []BindTechnique
	index          int
}

func (bts *BindTechniquesStruct) CopyNew() *BindTechniquesStruct {
	bts.Lock()
	defer bts.Unlock()
	newBts := &BindTechniquesStruct{
		bindTechniques: map[BindTechnique]bool{},
		sorted:         make([]BindTechnique, len(bts.sorted)),
	}
	for k, v := range bts.sorted {
		newBts.sorted[k] = v
	}
	for k, v := range bts.bindTechniques {
		newBts.bindTechniques[k] = v
	}
	return newBts
}

func (bts *BindTechniquesStruct) Add(bt BindTechnique) {
	bts.Lock()
	defer bts.Unlock()

	if bts.bindTechniques == nil {
		bts.bindTechniques = map[BindTechnique]bool{}
	}

	bts.bindTechniques[bt] = true
	bts.sorted = []BindTechnique{}
	for bt, _ := range bts.bindTechniques {
		bts.sorted = append(bts.sorted, bt)
	}
	sort.Sort(bts)
}

func (bts *BindTechniquesStruct) Next() BindTechnique {
	bts.Lock()
	defer bts.Unlock()

	if len(bts.sorted) == 0 {
		return BindSTUN
	} else {
		bt := bts.sorted[bts.index%len(bts.sorted)]
		bts.index++
		return bt
	}
}

func (bts *BindTechniquesStruct) Len() int {
	return len(bts.bindTechniques)
}

func (bts *BindTechniquesStruct) Less(i, j int) bool {
	return bts.sorted[i].Priority() < bts.sorted[j].Priority()
}

func (bts *BindTechniquesStruct) Swap(i, j int) {
	tmp := bts.sorted[i]
	bts.sorted[i] = bts.sorted[j]
	bts.sorted[j] = tmp
}

var BindTechniques = BindTechniquesStruct{}
