//+build integration,linux

package nflog

import (
	"context"
	"testing"
	"time"
)

func TestLinuxNflog(t *testing.T) {
	//Set configuration parameters
	config := Config{
		Group:    100,
		Copymode: CopyPacket,
	}
	// Open a socket to the netfilter log subsystem
	nf, err := Open(&config)
	if err != nil {
		t.Fatalf("failed to open nflog socket: %v", err)
	}
	defer nf.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fn := func(a Attribute) int {
		// Just print out the payload of the nflog packet
		t.Logf("%v\n", *a.Payload)
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

func startNflog(ctx context.Context, t *testing.T, group uint16) (func(), error) {
	t.Helper()

	config := Config{
		Group:    group,
		Copymode: CopyPacket,
	}

	nf, err := Open(&config)
	if err != nil {
		return func() {}, err
	}
	fn := func(a Attribute) int {
		t.Logf("--nflog-group %d\t%v\n", group, *a.Payload)
		return 1
	}

	err = nf.Register(ctx, fn)
	if err != nil {
		return func() {}, err
	}

	return func() { nf.Close() }, nil
}

func TestLinuxMultiNflog(t *testing.T) {
	var cleanUp []func()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for i := 32; i <= 42; i++ {
		function, err := startNflog(ctx, t, uint16(i))
		if err != nil {
			t.Fatalf("failed to open nflog socket for group %d: %v", i, err)
		}
		cleanUp = append(cleanUp, function)
	}

	// Block till the context expires
	<-ctx.Done()

	for _, function := range cleanUp {
		function()
	}
}
