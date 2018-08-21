//+build linux

package nflog

import "errors"

// Various Copy modes
const (
	NfUlnlCopyNone   byte = 0x00
	NfUlnlCopyMeta   byte = 0x01
	NfUlnlCopyPacket byte = 0x02

	NfUlnlCfgFSeq       byte = 0x0001
	NfUlnlCfgFSeqGlobal byte = 0x0002
	NfUlnlCfgFConntrack byte = 0x0004
)

// Various errors
var (
	ErrAfFamily = errors.New("Unsupported AF_Family type")
	ErrCopyMode = errors.New("Unsupported copy mode")
)

// nfLogSubSysUlog the netlink subsystem we will query
const nfnlSubSysUlog = 0x04

// Message types
const (
	// Kernel to userspace
	nfUlnlMsgPacket = 0x0
	// Userspace to kernel
	nfUlnlMsgConfig = 0x1
)

const (
	nfUlACfgUnspec    = 0x0
	nfUlACfgCmd       = 0x1
	nfUlACfgMode      = 0x2
	nfUlACfgNlBufSize = 0x3
	nfUlACfgTimeOut   = 0x4 /* in 1/100 s */
	nfUlACfgQThresh   = 0x5
	nfUlACfgFlags     = 0x6
)

const (
	nfUlnlCfgCmdNone     = 0x0
	nfUlnlCfgCmdBind     = 0x1
	nfUlnlCfgCmdUnbind   = 0x2
	nfUlnlCfgCmdPfBind   = 0x3
	nfUlnlCfgCmdPfUnbind = 0x4
)

const (
	nfUcketHdr             = 1
	nfUlaAttrMark          = 2
	nfUlaAttrTimestamp     = 3
	nfUlaAttrIfindexIndev  = 4
	nfUlaAttrIfindexOutdev = 5
	nfUlaAttrHwaddr        = 6
	nfUlaAttrPayload       = 7
	nfUlaAttrPrefix        = 8
	nfUlaAttrUID           = 9
	nfUlaAttrSeq           = 10
	nfUlaAttrSeqGlobal     = 11
	nfUlaAttrGID           = 12
	nfUlaAttrHwType        = 13
	nfUlaAttrHwHeader      = 14
	nfUlaAttrHwLen         = 15
	nfUlaAttrCt            = 16
	nfUlaAttrCtInfo        = 17
)
