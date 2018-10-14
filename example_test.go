//+build linux

package nflog_test

import (
	"context"
	"fmt"
	"time"

	nfl "github.com/florianl/go-nflog"
	"golang.org/x/sys/unix"
)

func ExampleNflog_Register() {
	// Send outgoing pings to nflog group 100
	// #iptables -I OUTPUT -p icmp -j NFLOG --nflog-group 100

	nflog, err := nfl.Open()
	if err != nil {
		fmt.Println("could not open nflog socket:", err)
		return
	}
	defer nflog.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Register your function to listen on nflog group 100
	err = nflog.Register(ctx, unix.AF_INET, 100, nfl.NfUlnlCopyPacket,
		func(m nfl.Msg) int { fmt.Printf("%#v\n", m); return 0 })
	if err != nil {
		fmt.Println(err)
		return
	}

	select {
	// Block till the context expires
	case <-ctx.Done():
	}
}
