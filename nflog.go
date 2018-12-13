//+build linux

package nflog

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

// Nflog represents a netfilter log handler
type Nflog struct {
	// Con is the pure representation of a netlink socket
	Con *netlink.Conn

	logger *log.Logger

	flags    []byte //uint16
	bufsize  []byte //uint32
	qthresh  []byte //uint32
	timeout  []byte //uint32
	group    uint16
	copyMode uint8
}

// devNull satisfies io.Writer, in case *log.Logger is not provided
type devNull struct{}

func (devNull) Write(p []byte) (int, error) {
	return 0, nil
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

	if config.Copymode != NfUlnlCopyNone && config.Copymode != NfUlnlCopyMeta && config.Copymode != NfUlnlCopyPacket {
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
	binary.BigEndian.PutUint16(nflog.flags, config.Flags)
	nflog.timeout = []byte{0x00, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint32(nflog.timeout, config.Timeout)
	nflog.bufsize = []byte{0x00, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint32(nflog.bufsize, config.Bufsize)
	nflog.qthresh = []byte{0x00, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint32(nflog.qthresh, config.QThresh)
	nflog.group = config.Group
	nflog.copyMode = config.Copymode

	return &nflog, nil
}

func checkFlags(flags uint16) error {
	if flags > NfUlnlCfgFConntrack {
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
type HookFunc func(m Msg) int

// Register your own function as callback for a netfilter log group
func (nflog *Nflog) Register(ctx context.Context, fn HookFunc) error {

	// unbinding existing handler (if any)
	seq, err := nflog.setConfig(unix.AF_UNSPEC, 0, 0, []netlink.Attribute{
		{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdPfUnbind}},
	})
	if err != nil {
		return err
	}

	// binding to family
	_, err = nflog.setConfig(unix.AF_UNSPEC, seq, 0, []netlink.Attribute{
		{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdPfBind}},
	})
	if err != nil {
		return err
	}

	// binding to generic group
	_, err = nflog.setConfig(unix.AF_UNSPEC, seq, 0, []netlink.Attribute{
		{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdBind}},
	})
	if err != nil {
		return err
	}

	// binding to the requested group
	_, err = nflog.setConfig(unix.AF_UNSPEC, seq, nflog.group, []netlink.Attribute{
		{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdBind}},
	})
	if err != nil {
		return err
	}

	// set copy mode and buffer size
	data := append(nflog.bufsize, nflog.copyMode)
	data = append(data, 0x0)
	_, err = nflog.setConfig(unix.AF_UNSPEC, seq, nflog.group, []netlink.Attribute{
		{Type: nfUlACfgMode, Data: data},
	})
	if err != nil {
		return err
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
			reply, err := nflog.Con.Receive()
			if err != nil {
				nflog.logger.Printf("Could not receive message: %v", err)
				continue
			}

			for _, msg := range reply {
				if msg.Header.Type == netlink.HeaderTypeDone {
					// this is the last message of a batch
					// continue to receive messages
					break
				}
				m, err := parseMsg(nflog.logger, msg)
				if err != nil {
					nflog.logger.Printf("Could not parse message: %v", err)
					continue
				}
				if ret := fn(m); ret != 0 {
					return
				}
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}()

	return nil
}

// /include/uapi/linux/netfilter/nfnetlink.h:struct nfgenmsg{} res_id is Big Endian
func putExtraHeader(familiy, version uint8, resid uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, resid)
	return append([]byte{familiy, version}, buf...)
}

func (nflog *Nflog) setConfig(afFamily uint8, oseq uint32, resid uint16, attrs []netlink.Attribute) (uint32, error) {
	cmd, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return 0, err
	}
	data := putExtraHeader(afFamily, unix.NFNETLINK_V0, resid)
	data = append(data, cmd...)
	req := netlink.Message{
		Header: netlink.Header{
			Type:     netlink.HeaderType((nfnlSubSysUlog << 8) | nfUlnlMsgConfig),
			Flags:    netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge,
			Sequence: oseq,
		},
		Data: data,
	}
	return nflog.execute(req)
}

// ErrMsg as defined in nlmsgerr
type ErrMsg struct {
	Code  int
	Len   uint32
	Type  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
}

func unmarschalErrMsg(b []byte) (ErrMsg, error) {
	var msg ErrMsg

	msg.Code = int(nlenc.Uint32(b[0:4]))
	msg.Len = nlenc.Uint32(b[4:8])
	msg.Type = nlenc.Uint16(b[8:10])
	msg.Flags = nlenc.Uint16(b[10:12])
	msg.Seq = nlenc.Uint32(b[12:16])
	msg.Pid = nlenc.Uint32(b[16:20])

	return msg, nil
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
			return 0, fmt.Errorf("Received more than one message from the kernel")
		}
		seq = msg.Header.Sequence
	}

	return seq, nil
}

func htonsU32(i uint32) []byte {
	buf := make([]byte, 4)
	nlenc.PutUint32(buf, i)
	return buf
}

func parseMsg(logger *log.Logger, msg netlink.Message) (Msg, error) {
	if msg.Header.Type&netlink.HeaderTypeError == netlink.HeaderTypeError {
		errMsg, err := unmarschalErrMsg(msg.Data)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%#v", errMsg)
	}
	m, err := extractAttributes(logger, msg.Data)
	if err != nil {
		return nil, err
	}
	return m, nil
}
