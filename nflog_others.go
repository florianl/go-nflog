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
	// Interface to log internals.
	Logger *log.Logger
}

// Msg contains all the information of a connection
type Msg map[int][]byte

// Open is not implemented for OS other than Linux
func Open(config *Config) (*Nflog, error) {
	return nil, errNotLinux
}

// Close is not implemented for OS other than Linux
func (_ *Nflog) Close() error {
	return errNotLinux
}

// HookFunc is a function, that receives events from a Netlinkgroup
type HookFunc func(_ Msg) int

// Register is not implemented for OS other than Linux
func (_ *Nflog) Register(_ context.Context, _, _ int, _ byte, _ HookFunc) error {
	return errNotLinux
}
