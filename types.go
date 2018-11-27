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
	nfUlnlMsgPacket = iota
	// Userspace to kernel
	nfUlnlMsgConfig
)

const (
	_ = iota
	nfUlACfgCmd
	nfUlACfgMode
	nfUlACfgNlBufSize
	nfUlACfgTimeOut /* in 1/100 s */
	nfUlACfgQThresh
	nfUlACfgFlags
)

const (
	_ = iota
	nfUlnlCfgCmdBind
	nfUlnlCfgCmdUnbind
	nfUlnlCfgCmdPfBind
	nfUlnlCfgCmdPfUnbind
)

const nlafNested = (1 << 15)

const (
	_ = iota
	nfUlaAttrPacketHdr
	nfUlaAttrMark
	nfUlaAttrTimestamp
	nfUlaAttrIfindexIndev
	nfUlaAttrIfindexOutdev
	nfUlaAttrIfindexPhysIndev
	nfUlaAttrIfindexPhysOutdev
	nfUlaAttrHwaddr
	nfUlaAttrPayload
	nfUlaAttrPrefix
	nfUlaAttrUID
	nfUlaAttrSeq
	nfUlaAttrSeqGlobal
	nfUlaAttrGID
	nfUlaAttrHwType
	nfUlaAttrHwHeader
	nfUlaAttrHwLen
	nfUlaAttrCt
	nfUlaAttrCtInfo
)

// Various identifier,that can be the key of Msg map
// A Msg map don't need to contain all of these keys.
const (
	AttrHwProtocol = iota
	AttrHook
	AttrMark
	AttrTimestamp
	AttrIfindexIndev
	AttrIfindexOutdev
	AttrIfindexPhysIndev
	AttrIfindexPhysOutdev
	AttrHwAddr
	AttrPayload
	AttrPrefix
	AttrUID
	AttrSeq
	AttrSeqGlobal
	AttrGID
	AttrHwType
	AttrHwHeader
	AttrHwLen
	AttrCt
	AttrCtInfo
)
