// +build !windows

package readpassword

import "golang.org/x/crypto/ssh/terminal"

func ReadPassword() string {
	bytePassword, _ := terminal.ReadPassword(0)
	password := string(bytePassword)
	return password
}
