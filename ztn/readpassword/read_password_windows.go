// +build windows

package readpassword

import (
	"bufio"
	"os"
	"strings"
)

func ReadPassword() string {
	reader := bufio.NewReader(os.Stdin)
	password, _ := reader.ReadString('\n')
	password = strings.Trim(password, "\r\n")
	return password
}
