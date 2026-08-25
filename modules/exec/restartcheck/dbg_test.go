package restartcheck

import (
	"context"
	"fmt"
	"testing"
)

func TestDbgKernels2(t *testing.T) {
	rt := rcRT(t, "debian")
	runner := &scriptedRunner{stdout: map[string]string{
		"uname -a":                                    "Linux host 6.1.0-16-amd64 #1 SMP Debian 6.1.0-16",
		"dpkg --get-selections linux-image-*":         "linux-image-6.1.0-16-amd64\t\tinstall\nlinux-image-6.1.0-17-amd64\t\tinstall\n",
		"apt-cache policy linux-image-6.1.0-16-amd64": "linux-image-6.1.0-16-amd64:\n  Installed: 6.1.0-16-amd64\n",
	}}
	rt.Runner = runner
	v := kernelVersionsDebian(context.Background(), rt)
	fmt.Printf("VERSIONS=%#v\n", v)

	fn := restartCheckFunc{}
	res, err := fn.Execute(context.Background(), rt, &RestartCheckArgs{})
	fmt.Printf("RES=%#v ERR=%v\n", res, err)
}
