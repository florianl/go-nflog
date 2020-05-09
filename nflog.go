package nflog

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"time"
	"unsafe"

	"github.com/florianl/go-nflog/internal/unix"

	"github.com/mdlayher/netlink"
)

// Nflog represents a netfilter log handler
type Nflog struct {
	// Con is the pure representation of a netlink socket
	Con *netlink.Conn

	logger *log.Logger

	flags          []byte //uint16
	bufsize        []byte //uint32
	qthresh        []byte //uint32
	timeout        []byte //uint32
	group          uint16
	copyMode       uint8
	settings       uint16
	setReadTimeout func() error
}

// devNull satisfies io.Writer, in case *log.Logger is not provided
type devNull struct{}

func (devNull) Write(p []byte) (int, error) {
	return 0, nil
}

// for detailes see https://github.com/tensorflow/tensorflow/blob/master/tensorflow/go/tensor.go#L488-L505
var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}

// Open a connection to the netfilter log subsystem
func Open(config *Config) (*Nflog, error) {
	var nflog Nflog

	if config == nil {
		config = &Config{}
	}

	if err := checkFlags(config.Flags); err != nil {
		return nil, err
	}

	if config.Copymode != CopyNone && config.Copymode != CopyMeta && config.Copymode != CopyPacket {
		return nil, ErrCopyMode
	}

	con, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{NetNS: config.NetNS})
	if err != nil {
		return nil, err
	}
	nflog.Con = con

	if config.Logger == nil {
		nflog.logger = log.New(new(devNull), "", 0)
	} else {
		nflog.logger = config.Logger
	}

	nflog.flags = []byte{0x00, 0x00}
	nativeEndian.PutUint16(nflog.flags, config.Flags)
	nflog.timeout = []byte{0x00, 0x00, 0x00, 0x00}
	nativeEndian.PutUint32(nflog.timeout, config.Timeout)
	nflog.bufsize = []byte{0x00, 0x00, 0x00, 0x00}
	nativeEndian.PutUint32(nflog.bufsize, config.Bufsize)
	nflog.qthresh = []byte{0x00, 0x00, 0x00, 0x00}
	nativeEndian.PutUint32(nflog.qthresh, config.QThresh)
	nflog.group = config.Group
	nflog.copyMode = config.Copymode
	nflog.settings = config.Settings

	if config.ReadTimeout > 0 {
		nflog.setReadTimeout = func() error {
			deadline := time.Now().Add(config.ReadTimeout)
			return nflog.Con.SetReadDeadline(deadline)
		}
	} else {
		nflog.setReadTimeout = func() error { return nil }
	}

	return &nflog, nil
}

func checkFlags(flags uint16) error {
	if flags > FlagConntrack {
		return ErrUnknownFlag
	}
	return nil
}

// Close the connection to the netfilter log subsystem
func (nflog *Nflog) Close() error {
	return nflog.Con.Close()
}

// HookFunc is a function, that receives events from a Netlinkgroup
// To stop receiving messages on this HookFunc, return something different than 0
type HookFunc func(a Attribute) int

// Register your own function as callback for a netfilter log group.
// Errors other than net.Timeout() will be reported via the provided log interface
// and the receiving of netfilter log messages will be stopped.
func (nflog *Nflog) Register(ctx context.Context, fn HookFunc) error {

	// unbinding existing handler (if any)
	seq, err := nflog.setConfig(unix.AF_UNSPEC, 0, 0, []netlink.Attribute{
		{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdPfUnbind}},
	})
	if err != nil {
		return fmt.Errorf("could not unbind existing handlers from socket: %v", err)
	}

	// binding to family
	_, err = nflog.setConfig(unix.AF_UNSPEC, seq, 0, []netlink.Attribute{
		{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdPfBind}},
	})
	if err != nil {
		return fmt.Errorf("could not bind socket to family: %v", err)
	}

	if (nflog.settings & GenericGroup) == GenericGroup {
		// binding to generic group
		_, err = nflog.setConfig(unix.AF_UNSPEC, seq, 0, []netlink.Attribute{
			{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdPfBind}},
		})
		if err != nil {
			return fmt.Errorf("could not bind to generic group: %v", err)
		}
	}

	// binding to the requested group
	_, err = nflog.setConfig(unix.AF_UNSPEC, seq, nflog.group, []netlink.Attribute{
		{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdBind}},
	})
	if err != nil {
		return fmt.Errorf("could not bind to requested group %d: %v", nflog.group, err)
	}

	// set copy mode and buffer size
	data := append(nflog.bufsize, nflog.copyMode)
	data = append(data, 0x0)
	_, err = nflog.setConfig(unix.AF_UNSPEC, seq, nflog.group, []netlink.Attribute{
		{Type: nfUlACfgMode, Data: data},
	})
	if err != nil {
		return fmt.Errorf("could not set copy mode %d and buffer size %d: %v", nflog.copyMode, nflog.bufsize, err)
	}

	var attrs []netlink.Attribute
	if nflog.flags[0] != 0 || nflog.flags[1] != 0 {
		// set flags
		attrs = append(attrs, netlink.Attribute{Type: nfUlACfgFlags, Data: nflog.flags})
	}

	if nflog.timeout[0] != 0 || nflog.timeout[1] != 0 || nflog.timeout[2] != 0 || nflog.timeout[3] != 0 {
		// set timeout
		attrs = append(attrs, netlink.Attribute{Type: nfUlACfgTimeOut, Data: nflog.timeout})

	}

	if nflog.qthresh[0] != 0 || nflog.qthresh[1] != 1 || nflog.qthresh[2] != 0 || nflog.qthresh[3] != 0 {
		// set qthresh
		attrs = append(attrs, netlink.Attribute{Type: nfUlACfgQThresh, Data: nflog.timeout})
	}

	if len(attrs) != 0 {
		_, err = nflog.setConfig(unix.AF_UNSPEC, seq, nflog.group, attrs)
		if err != nil {
			return err
		}
	}
	go func() {
		defer func() {
			// unbinding from group
			_, err = nflog.setConfig(unix.AF_UNSPEC, seq, nflog.group, []netlink.Attribute{
				{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdUnbind}},
			})
			if err != nil {
				nflog.logger.Printf("Could not unbind socket from configuration: %v", err)
				return
			}
		}()
		for {
			if err := ctx.Err(); err != nil {
				nflog.logger.Printf("Stop receiving nflog messages: %v", err)
				return
			}
			nflog.setReadTimeout()
			reply, err := nflog.Con.Receive()
			if err != nil {
				if opError, ok := err.(*netlink.OpError); ok {
					if opError.Timeout() || opError.Temporary() {
						continue
					}
				}
				nflog.logger.Printf("Could not receive message: Unexpected error: %v", err)
				return
			}

			for _, msg := range reply {
				if msg.Header.Type == netlink.Done {
					// this is the last message of a batch
					// continue to receive messages
					break
				}
				attrs, err := parseMsg(nflog.logger, msg)
				if err != nil {
					nflog.logger.Printf("Could not parse message: %v", err)
					continue
				}
				if ret := fn(attrs); ret != 0 {
					return
				}
			}
		}
	}()

	return nil
}

// /include/uapi/linux/netfilter/nfnetlink.h:struct nfgenmsg{}
func putExtraHeader(familiy, version uint8, resid uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, resid)
	return append([]byte{familiy, version}, buf...)
}

func (nflog *Nflog) setConfig(afFamily uint8, oseq uint32, resid uint16, attrs []netlink.Attribute) (uint32, error) {
	ad := netlink.NewAttributeEncoder()

	for _, attr := range attrs {
		ad.Bytes(attr.Type, attr.Data)
	}
	cmd, err := ad.Encode()
	if err != nil {
		return 0, err
	}
	data := putExtraHeader(afFamily, unix.NFNETLINK_V0, resid)
	data = append(data, cmd...)
	req := netlink.Message{
		Header: netlink.Header{
			Type:     netlink.HeaderType((nfnlSubSysUlog << 8) | nfUlnlMsgConfig),
			Flags:    netlink.Request | netlink.Acknowledge,
			Sequence: oseq,
		},
		Data: data,
	}
	return nflog.execute(req)
}

func (nflog *Nflog) execute(req netlink.Message) (uint32, error) {
	var seq uint32

	reply, e := nflog.Con.Execute(req)
	if e != nil {
		return 0, e
	}

	if e := netlink.Validate(req, reply); e != nil {
		return 0, e
	}
	for _, msg := range reply {
		if seq != 0 {
			return 0, fmt.Errorf("received more than one message from the kernel")
		}
		seq = msg.Header.Sequence
	}

	return seq, nil
}

func parseMsg(logger *log.Logger, msg netlink.Message) (Attribute, error) {
	a, err := extractAttributes(logger, msg.Data)
	if err != nil {
		return Attribute{}, err
	}
	return a, nil
}
