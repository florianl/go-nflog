package nflog_test

import (
	"context"
	"fmt"

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

	// Register your function to listen on nflog group 100
	err = nflog.Register(context.Background(), unix.AF_INET, 100, nfl.NfUlnlCopyPacket,
		func(m nfl.Msg) int { fmt.Printf("%#v\n", m); return 0 })
	if err != nil {
		fmt.Println(err)
		return
	}
}
