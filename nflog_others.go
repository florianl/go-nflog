//+build !linux

package nflog

import (
	"context"
	"errors"
	"log"
)

var errNotLinux = errors.New("Not implemented for OS other than linux")

// Nflog is not implemented for OS other than linux
type Nflog struct{}

// Config contains options for a Conn.
type Config struct {
	// Network namespace the Nflog needs to operate in. If set to 0 (default),
	// no network namespace will be entered.
	NetNS int

	// Optional flags
	Flags uint16

	// Specifies the number of packets in the group,
	// until they will be pushed to userspace.
	QThresh uint32

	// Maximum time in 1/100s that a packet in the nflog group will be queued,
	// until it is pushed to userspace.
	Timeout uint32

	// Nflog group this socket will be assigned to.
	Group uint16

	// Specifies how the kernel handles a packet in the nflog group.
	Copymode uint8

	// If NfUlnlCopyPacket is set as CopyMode,
	// this parameter specifies the maximum number of bytes,
	// that will be copied to userspace.
	Bufsize uint32

	// Interface to log internals.
	Logger *log.Logger
}

// Msg contains all the information of a connection
type Msg map[int][]byte

// Open is not implemented for OS other than Linux
func Open(_ *Config) (*Nflog, error) {
	return nil, errNotLinux
}

// Close is not implemented for OS other than Linux
func (_ *Nflog) Close() error {
	return errNotLinux
}

// HookFunc is a function, that receives events from a Netlinkgroup
type HookFunc func(_ Msg) int

// Register is not implemented for OS other than Linux
func (_ *Nflog) Register(_ context.Context, _ HookFunc) error {
	return errNotLinux
}
