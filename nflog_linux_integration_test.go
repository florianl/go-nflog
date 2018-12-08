//+build integration,linux

package nflog

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestLinuxNflog(t *testing.T) {
	//Set configuration parameters
	config := Config{
		Group:    100,
		Copymode: NfUlnlCopyPacket,
	}
	// Open a socket to the netfilter log subsystem
	nf, err := Open(&config)
	if err != nil {
		t.Fatalf("failed to open nflog socket: %v", err)
	}
	defer nf.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fn := func(m Msg) int {
		// Just print out the payload of the nflog packet
		fmt.Printf("%v\n", m[AttrPayload])
		return 0
	}

	// Register your function to listen on nflog group 100
	err = nf.Register(ctx, fn)
	if err != nil {
		t.Fatalf("failed to register hook function: %v", err)
	}

	// Block till the context expires
	<-ctx.Done()
}
