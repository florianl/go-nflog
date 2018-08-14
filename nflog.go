//+build linux

package nflog

import (
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Nflog represents a netfilter log handler
type Nflog struct {
	// Con is the pure representation of a netlink socket
	Con *netlink.Conn
}

// Open a connection to the netfilter subsystem
func Open() (*Nflog, error) {
	var nflog Nflog

	con, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, err
	}
	nflog.Con = con

	return &nflog, nil
}

// Close the connection to the conntrack subsystem
func (nflog *Nflog) Close() error {
	return nflog.Con.Close()
}
