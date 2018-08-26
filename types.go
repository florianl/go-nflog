//+build linux

package nflog

import "errors"

// Various Copy modes
const (
	NfUlnlCopyNone   byte = 0x00
	NfUlnlCopyMeta   byte = 0x01
	NfUlnlCopyPacket byte = 0x02

	// Flags that can be set on a connection
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

// Various identifier,that can be the key of Msg map
const (
	NfUlaAttrPacketHdr         = 1
	NfUlaAttrMark              = 2
	NfUlaAttrTimestamp         = 3
	NfUlaAttrIfindexIndev      = 4
	NfUlaAttrIfindexOutdev     = 5
	NfUlaAttrIfindexPhysIndev  = 6
	NfUlaAttrIfindexPhysOutdev = 7
	NfUlaAttrHwaddr            = 8
	NfUlaAttrPayload           = 9
	NfUlaAttrPrefix            = 10
	NfUlaAttrUID               = 11
	NfUlaAttrSeq               = 12
	NfUlaAttrSeqGlobal         = 13
	NfUlaAttrGID               = 14
	NfUlaAttrHwType            = 15
	NfUlaAttrHwHeader          = 16
	NfUlaAttrHwLen             = 17
	NfUlaAttrCt                = 18
	NfUlaAttrCtInfo            = 19
)
