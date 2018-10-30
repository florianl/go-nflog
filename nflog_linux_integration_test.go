//+build integration,linux

package nflog

import (
	"context"
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLinuxNflog(t *testing.T) {
	// Open a socket to the netfilter log subsystem
	nf, err := Open()
	if err != nil {
		t.Fatalf("failed to open nflog socket: %v", err)
	}
	defer nf.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fn := func(m Msg) int {
		// Just print out the payload of the nflog packet
		fmt.Printf("%v\n", m[NfUlaAttrPayload])
		return 0
	}

	// Register your function to listen on nflog group 100
	err = nf.Register(ctx, unix.AF_INET, 100, NfUlnlCopyPacket, fn)
	if err != nil {
		t.Fatalf("failed to register hook function: %v", err)
	}

	select {
	// Block till the context expires
	case <-ctx.Done():
	}
}
