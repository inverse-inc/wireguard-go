package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"strings"

	"golang.org/x/sys/windows"
	"github.com/inverse-inc/wireguard-go/outputlog"
)

func run() {

	//TODO: get rid of run.bat since this elevates by itself now
	cmd := exec.Command("C:\\Program Files\\PacketFence-Zero-Trust-Client\\run.bat", wgenv.Name())
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	fmt.Println(cmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Start()
	wireguardCmd = cmd
	cmd.Wait()
}

func elevate() {
	if amAdmin() {
		outputlog.RedirectOutputToFilePrefix("C:\\Program Files\\PacketFence-Zero-Trust-Client\\guiwrapper")
		return
	}

	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)
	
	var showCmd int32 = 1 //SW_NORMAL
	
	err := windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
	if err != nil {
		fmt.Println(err)
	}

	os.Exit(0)
}

func amAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		fmt.Println("admin no")
		return false
	}
	fmt.Println("admin yes")
	return true
}