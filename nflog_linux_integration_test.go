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
		Group:       100,
		Copymode:    NfUlnlCopyPacket,
		ReadTimeout: 10 * time.Millisecond,
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
		t.Logf("%v\n", m[AttrPayload])
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

func startNflog(t *testing.T, group uint16) (func(), error) {
	config := Config{
		Group:       group,
		Copymode:    NfUlnlCopyPacket,
		ReadTimeout: 10 * time.Millisecond,
	}

	nf, err := Open(&config)
	if err != nil {
		return func() {}, err
	}
	fn := func(m Msg) int {
		t.Logf("--nflog-group %d\t%v\n", group, m[AttrPayload])
		return 1
	}

	err = nf.Register(context.Background(), fn)
	if err != nil {
		return func() {}, err
	}

	return func() { nf.Close() }, nil
}

func TestLinuxMultiNflog(t *testing.T) {
	var cleanUp []func()

	for i := 1; i <= 42; i++ {
		function, err := startNflog(t, uint16(i))
		if err != nil {
			t.Fatalf("failed to open nflog socket for group %d: %v", i, err)
		}
		cleanUp = append(cleanUp, function)
	}

	time.Sleep(5 * time.Second)

	for _, function := range cleanUp {
		function()
	}
}
