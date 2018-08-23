//+build linux

package nflog

import "errors"

// Various Copy modes
const (
	NfUlnlCopyNone   byte = 0x00
	NfUlnlCopyMeta   byte = 0x01
	NfUlnlCopyPacket byte = 0x02

	NfUlnlCfgFSeq       uint16 = 0x0001
	NfUlnlCfgFSeqGlobal uint16 = 0x0002
	NfUlnlCfgFConntrack uint16 = 0x0004
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
	nfUlaAttrPacketHdr         = 1
	nfUlaAttrMark              = 2
	nfUlaAttrTimestamp         = 3
	nfUlaAttrIfindexIndev      = 4
	nfUlaAttrIfindexOutdev     = 5
	nfUlaAttrIfindexPhysIndev  = 6
	nfUlaAttrIfindexPhysOutdev = 7
	nfUlaAttrHwaddr            = 8
	nfUlaAttrPayload           = 9
	nfUlaAttrPrefix            = 10
	nfUlaAttrUID               = 11
	nfUlaAttrSeq               = 12
	nfUlaAttrSeqGlobal         = 13
	nfUlaAttrGID               = 14
	nfUlaAttrHwType            = 15
	nfUlaAttrHwHeader          = 16
	nfUlaAttrHwLen             = 17
	nfUlaAttrCt                = 18
	nfUlaAttrCtInfo            = 19
)
