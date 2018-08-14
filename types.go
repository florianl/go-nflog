//+build linux

package nflog

import "errors"

// Various Copy modes
const (
	NfLogCopyNone   byte = 0x00
	NfLogCopyMeta   byte = 0x01
	NfLogCopyPacket byte = 0x02

	_nfLogCopyMax = 0x03
)

// Various errors
var (
	ErrAfFamily = errors.New("Unsupported AF_Family type")
	ErrCopyMode = errors.New("Unsupported copy mode")
)

// nfLogSubSysUlog the netlink subsystem we will query
const nfLogSubSysUlog = 0x04

// Message types
const (
	// Kernel to userspace
	nfLogMsgPacket = 0x0
	// Userspace to kernel
	nfLogMsgConfig = 0x1
)

const (
	nfLogCfgUnspec    = 0x0
	nfLogCfgCmd       = 0x1
	nfLogCfgMode      = 0x2
	nfLogCfgNlBufSize = 0x3
	nfLogCfgTimeOut   = 0x4 /* in 1/100 s */
	nfLogCfgQThresh   = 0x5
	nfLogCfgFlags     = 0x6
)

const (
	nfLogCfgCmdNone     = 0x0
	nfLogCfgCmdBind     = 0x1
	nfLogCfgCmdUnbind   = 0x2
	nfLogCfgCmdPfBind   = 0x3
	nfLogCfgCmdPfUnbind = 0x4
)
