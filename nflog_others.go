//+build !linux

package nflog

import (
	"context"
	"errors"
)

var errNotLinux = errors.New("Not implemented for OS other than linux")

// Nflog is not implemented for OS other than linux
type Nflog struct{}

// Open is not implemented for OS other than Linux
func Open(_ *Config) (*Nflog, error) {
	return nil, errNotLinux
}

// Close is not implemented for OS other than Linux
func (_ *Nflog) Close() error {
	return errNotLinux
}

// HookFunc is a function, that receives events from a Netlinkgroup
type HookFunc func(_ Attribute) int

// Register is not implemented for OS other than Linux
func (_ *Nflog) Register(_ context.Context, _ HookFunc) error {
	return errNotLinux
}
