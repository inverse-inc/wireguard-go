package outputlog

import (
	"fmt"
	"os"
	"time"

	"github.com/inverse-inc/packetfence/go/sharedutils"
	"gopkg.in/natefinch/lumberjack.v2"
)

func RedirectOutputToFilePrefix(fname string) {
	RedirectOutputToFile(fmt.Sprintf("%s-%d.log", fname, time.Now().Unix()))
}
func RedirectOutputToFile(fname string) {
	f, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	sharedutils.CheckError(err)
	os.Stdout = f
	os.Stderr = f
}
func RedirectOutputToRotatedLog(fname string) {
	r, w, err := os.Pipe()
	sharedutils.CheckError(err)

	l := &lumberjack.Logger{
		Filename:   fname,
		MaxSize:    10, //megabytes
		MaxBackups: 5,
	}
	os.Stdout = w
	os.Stderr = w

	go func() {
		buf := make([]byte, 5000)
		for {
			n, err := r.Read(buf)
			sharedutils.CheckError(err)
			l.Write(buf[:n])
		}
	}()
}
