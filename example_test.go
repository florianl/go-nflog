//+build linux

package nflog_test

import (
	"context"
	"fmt"
	"time"

	"github.com/florianl/go-nflog"
)

func ExampleNflog_Register() {
	// Send outgoing pings to nflog group 100
	// # sudo iptables -I OUTPUT -p icmp -j NFLOG --nflog-group 100

	//Set configuration parameters
	config := nflog.Config{
		Group:    100,
		Copymode: nflog.NfUlnlCopyPacket,
	}

	nf, err := nflog.Open(&config)
	if err != nil {
		fmt.Println("could not open nflog socket:", err)
		return
	}
	defer nf.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fn := func(m nflog.Msg) int {
		fmt.Printf("%v\n", m[nflog.AttrPayload])
		return 0
	}

	// Register your function to listen on nflog group 100
	err = nf.Register(ctx, fn)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Block till the context expires
	<-ctx.Done()
}
