//+build linux

package nflog

import (
	"context"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRegister(t *testing.T) {
	tests := []struct {
		name     string
		family   int
		group    int
		copyMode byte
		fn       HookFunc
		err      error
	}{
		{name: "InvalidFamily", family: 3, fn: func(m Msg) int { return 0 }, err: ErrAfFamily},
		{name: "InvalidCopymode", family: unix.AF_INET6, copyMode: byte(0x5), fn: func(m Msg) int { return 0 }, err: ErrCopyMode},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nflog := &Nflog{}
			err := nflog.Register(context.Background(), tc.family, tc.group, tc.copyMode, tc.fn)
			if err != tc.err {
				t.Fatalf("Unexpected error - want: %v\tgot: %v\n", tc.err, err)
			}

		})
	}
}
