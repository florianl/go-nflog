package nflog

import "errors"

// Various constants
const (
	// Available copy modes
	NfUlnlCopyNone   byte = 0x00
	NfUlnlCopyMeta   byte = 0x01
	NfUlnlCopyPacket byte = 0x02 // Provides a complete copy of the packet in the Msg map

	// Flags that can be set on a connection
	NfUlnlCfgFSeq       uint16 = 0x0001
	NfUlnlCfgFSeqGlobal uint16 = 0x0002
	NfUlnlCfgFConntrack uint16 = 0x0004 // Requires Linux Kernel v4.4 or newer
)

// Various errors
var (
	ErrAfFamily    = errors.New("Unsupported AF_Family type")
	ErrCopyMode    = errors.New("Unsupported copy mode")
	ErrUnknownFlag = errors.New("Unsupported flag")
	ErrNoTimestamp = errors.New("Timestamp was not set")
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
// A Msg map don't need to contain all of these keys.
const (
	attrUnspec                 = iota
	NfUlaAttrPacketHdr         = iota
	NfUlaAttrMark              = iota
	NfUlaAttrTimestamp         = iota
	NfUlaAttrIfindexIndev      = iota
	NfUlaAttrIfindexOutdev     = iota
	NfUlaAttrIfindexPhysIndev  = iota
	NfUlaAttrIfindexPhysOutdev = iota
	NfUlaAttrHwaddr            = iota
	NfUlaAttrPayload           = iota
	NfUlaAttrPrefix            = iota
	NfUlaAttrUID               = iota
	NfUlaAttrSeq               = iota
	NfUlaAttrSeqGlobal         = iota
	NfUlaAttrGID               = iota
	NfUlaAttrHwType            = iota
	NfUlaAttrHwHeader          = iota
	NfUlaAttrHwLen             = iota
	NfUlaAttrCt                = iota
	NfUlaAttrCtInfo            = iota

	attrMax = iota /* This is for internal use only	*/

)
