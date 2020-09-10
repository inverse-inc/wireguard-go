// +build linux

package main

import "os"

func setenv(k, v string) {
	os.Setenv(k, v)
}
