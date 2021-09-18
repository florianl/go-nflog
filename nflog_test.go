//go:build linux
// +build linux

package nflog

import (
	"testing"
)

func TestOpen(t *testing.T) {
	tests := []struct {
		name     string
		group    uint16
		copymode uint8
		err      error
		flags    uint16
	}{
		{name: "InvalidCopymode", copymode: 0x5, err: ErrCopyMode},
		{name: "InvalidFlags", flags: 0x5, err: ErrUnknownFlag},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := Config{
				Copymode: tc.copymode,
				Group:    tc.group,
				Flags:    tc.flags,
			}
			_, err := Open(&config)
			if err != tc.err {
				t.Fatalf("Unexpected error - want: %v\tgot: %v\n", tc.err, err)
			}

		})
	}
}
