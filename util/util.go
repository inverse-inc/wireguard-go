package util

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/inverse-inc/packetfence/go/sharedutils"
)

func CheckGUIIsAliveUNIX(quit func()) {
	for {
		ppid64, err := strconv.Atoi(os.Getenv("WG_GUI_PID"))
		sharedutils.CheckError(err)
		ppid := int(ppid64)
		if !CheckPIDIsAlive(ppid) {
			fmt.Println("Parent process is dead, exiting")
			quit()
		}
		time.Sleep(1 * time.Second)
	}
}

func CheckGUIIsAliveWindows(quit func()) {
	for {
		ppid64, err := strconv.Atoi(os.Getenv("WG_GUI_PID"))
		sharedutils.CheckError(err)
		if !CheckPIDIsAlive(int(ppid64)) {
			fmt.Println("GUI is dead, exiting", ppid64)
			quit()
		}
		time.Sleep(1 * time.Second)
	}
}

func Pause() {
	time.Sleep(365 * 24 * time.Hour)
}
