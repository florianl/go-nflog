//+build linux

package nflog_test

import (
	"context"
	"fmt"
	"time"

	"github.com/florianl/go-nflog"
	"golang.org/x/sys/unix"
)

func ExampleNflog_Register() {
	// Send outgoing pings to nflog group 100
	// # sudo iptables -I OUTPUT -p icmp -j NFLOG --nflog-group 100

	nf, err := nflog.Open()
	if err != nil {
		fmt.Println("could not open nflog socket:", err)
		return
	}
	defer nf.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fn := func(m nflog.Msg) int {
		ts, err := m.Timestamp()
		if err != nflog.ErrNoTimestamp {
			ts = time.Now()
		}
		fmt.Printf("%s\t%v\n", ts, m[nflog.NfUlaAttrPayload])
		return 0
	}

	// Register your function to listen on nflog group 100
	err = nf.Register(ctx, unix.AF_INET, 100, nflog.NfUlnlCopyPacket, fn)
	if err != nil {
		fmt.Println(err)
		return
	}

	select {
	// Block till the context expires
	case <-ctx.Done():
	}
}
