package outputlog

import(
	"fmt"
	"os"
	"time"

	"github.com/inverse-inc/packetfence/go/sharedutils"
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