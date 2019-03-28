package nflog

import (
	"errors"
	"log"
	"time"
)

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

// Various optional settings
const (
	GenericGroup uint16 = 0x1
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

// Config contains options for a Conn.
type Config struct {
	// Network namespace the Nflog needs to operate in. If set to 0 (default),
	// no network namespace will be entered.
	NetNS int

	// Optional flags for the nflog communication
	Flags uint16

	// Specifies the number of packets in the group,
	// until they will be pushed to userspace.
	QThresh uint32

	// Maximum time in 1/100s that a packet in the nflog group will be queued,
	// until it is pushed to userspace.
	Timeout uint32

	// Nflog group this socket will be assigned to.
	Group uint16

	// Specifies how the kernel handles a packet in the nflog group.
	Copymode uint8

	// If NfUlnlCopyPacket is set as CopyMode,
	// this parameter specifies the maximum number of bytes,
	// that will be copied to userspace.
	Bufsize uint32

	// Optional settings to enable/disable features
	Settings uint16

	// Time till a read action times out
	ReadTimeout time.Duration

	// Interface to log internals.
	Logger *log.Logger
}

// Msg contains all the information of a connection
type Msg map[int]interface{}
