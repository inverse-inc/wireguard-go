package util

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/inverse-inc/packetfence/go/sharedutils"
)

func CheckParentIsAliveUNIX(quit func()) {
	for {
		ppid64, err := strconv.Atoi(os.Getenv("WG_GUI_PID"))
		sharedutils.CheckError(err)
		ppid := int(ppid64)
		process, err := os.FindProcess(ppid)
		if err != nil || ppid == 1 {
			fmt.Println("Parent process is dead, exiting")
			quit()
		} else if err := process.Signal(syscall.Signal(0)); err != nil {
			fmt.Println("Parent process is dead, exiting")
			quit()
		}
		time.Sleep(1 * time.Second)
	}
}
