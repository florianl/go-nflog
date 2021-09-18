//go:build linux
// +build linux

package nflog_test

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/florianl/go-nflog/v2"
)

func ExampleNflog_Register() {
	// Send outgoing pings to nflog group 100
	// # sudo iptables -I OUTPUT -p icmp -j NFLOG --nflog-group 100

	//Set configuration parameters
	config := nflog.Config{
		Group:    100,
		Copymode: nflog.CopyPacket,
	}

	nf, err := nflog.Open(&config)
	if err != nil {
		fmt.Println("could not open nflog socket:", err)
		return
	}
	defer nf.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// hook that is called for every received packet by the nflog group
	hook := func(attrs nflog.Attribute) int {
		// Just print out the payload of the nflog packet
		fmt.Fprintf(os.Stdout, "%#v\n", attrs.Payload)
		return 0
	}

	// errFunc that is called for every error on the registered hook
	errFunc := func(e error) int {
		// Just log the error and return 0 to continue receiving packets
		fmt.Fprintf(os.Stderr, "received error on hook: %v", e)
		return 0
	}

	// Register your function to listen on nflog group 100
	err = nf.RegisterWithErrorFunc(ctx, hook, errFunc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to register hook function: %v", err)
		return
	}

	// Block till the context expires
	<-ctx.Done()
}
