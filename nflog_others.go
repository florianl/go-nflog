//+build !linux

package nflog

import (
	"context"
	"errors"
)

var errNotLinux = errors.New("Not implemented for OS other than linux")

// Nflog is not implemented for OS other than linux
type Nflog struct{}

// Msg contains all the information of a connection
type Msg map[int][]byte

// Open is not implemented for OS other than Linux
func Open() (*Nflog, error) {
	return nil, errNotLinux
}

// Close is not implemented for OS other than Linux
func (nflog *Nflog) Close() error {
	return errNotLinux
}

// HookFunc is a function, that receives events from a Netlinkgroup
type HookFunc func(m Msg) int

// Register is not implemented for OS other than Linux
func (nflog *Nflog) Register(_ context.Context, _, _ int, _ byte, _ HookFunc) error {
	return errNotLinux
}
