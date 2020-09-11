package util

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
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
		cmd := exec.Command("tasklist")
		output, err := cmd.Output()
		if err != nil {
			fmt.Println("Unable to run tasklist: ", err, string(output))
		}
		if !regexp.MustCompile(os.Getenv("WG_GUI_WINDOWS_PROCESS_NAME") + `\s+` + os.Getenv("WG_GUI_PID") + `\s+`).Match(output) {
			fmt.Println("GUI is dead, exiting")
			quit()
		}
		time.Sleep(1 * time.Second)
	}
}
