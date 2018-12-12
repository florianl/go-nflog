package nflog

import "errors"

// Various constants
const (
	// Available copy modes for Config.Copymode.
	NfUlnlCopyNone byte = 0x00
	NfUlnlCopyMeta byte = 0x01
	// Provides a complete copy of the packet in the Msg map.
	// But can be limited by setting Config.Bufsize.
	NfUlnlCopyPacket byte = 0x02

	// Flags that can be set on a connection
	NfUlnlCfgFSeq       uint16 = 0x0001
	NfUlnlCfgFSeqGlobal uint16 = 0x0002
	// Requires Kernel configuration of CONFIG_NETFILTER_NETLINK_GLUE_CT
	NfUlnlCfgFConntrack uint16 = 0x0004
)

// Various errors
var (
	ErrCopyMode    = errors.New("Unsupported copy mode")
	ErrUnknownFlag = errors.New("Unsupported flag")
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
