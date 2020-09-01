// +build !windows

package ztn

import "golang.org/x/crypto/ssh/terminal"

func ReadPassword() string {
	bytePassword, _ := terminal.ReadPassword(0)
	password := string(bytePassword)
}
