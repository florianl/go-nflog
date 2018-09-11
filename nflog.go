//+build linux

package nflog

import (
	"context"
	"errors"
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

// Nflog represents a netfilter log handler
type Nflog struct {
	// Con is the pure representation of a netlink socket
	Con *netlink.Conn

	flags   []byte // uint16
	bufsize []byte //uint32
	qthresh []byte //uint32
	timeout []byte //uint32
}

// Various errors
var (
	ErrUnknownFlag = errors.New("Can not set flag")
)

// Msg contains all the information of a connection
type Msg map[int][]byte

// Open a connection to the netfilter subsystem
func Open() (*Nflog, error) {
	var nflog Nflog

	con, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, err
	}
	nflog.Con = con

	nflog.flags = make([]byte, 2)
	nflog.timeout = make([]byte, 4)
	nflog.bufsize = make([]byte, 4)
	nflog.qthresh = make([]byte, 4)

	return &nflog, nil
}

// Close the connection to the conntrack subsystem
func (nflog *Nflog) Close() error {
	return nflog.Con.Close()
}

// SetQThresh sets the queue thresh for this connection
func (nflog *Nflog) SetQThresh(qthresh uint32) error {
	nflog.qthresh = htonsU32(qthresh)
	return nil
}

// SetNlBufSize set the buffer size for this netlink connection
func (nflog *Nflog) SetNlBufSize(size uint32) error {
	nflog.bufsize = htonsU32(size)
	return nil
}

// SetTimeout in 1/100 s for this connection
func (nflog *Nflog) SetTimeout(timeout uint32) error {
	nflog.timeout = htonsU32(timeout)
	return nil
}

// SetFlag sets a specified flags on this connection
func (nflog *Nflog) SetFlag(flag uint16) error {
	if flag != NfUlnlCfgFSeq && flag != NfUlnlCfgFSeqGlobal && flag != NfUlnlCfgFConntrack {
		return ErrUnknownFlag
	}
	nflog.flags[0] |= byte(flag)
	return nil
}

// RemoveAllFlags deletes all flags, that were set on this connection
func (nflog *Nflog) RemoveAllFlags() error {
	nflog.flags = []byte{0x0, 0x0}
	return nil
}

// HookFunc is a function, that receives events from a Netlinkgroup
// To stop receiving messages on this HookFunc, return something different than 0
type HookFunc func(m Msg) int

// Register your own function as callback for a netfilter log group
func (nflog *Nflog) Register(ctx context.Context, afFamily, group int, copyMode byte, fn HookFunc) error {

	if afFamily != unix.AF_INET6 && afFamily != unix.AF_INET {
		return ErrAfFamily
	}

	if copyMode != NfUlnlCopyNone && copyMode != NfUlnlCopyMeta && copyMode != NfUlnlCopyPacket {
		return ErrCopyMode
	}

	// unbinding existing handler (if any)
	seq, err := nflog.setConfig(uint8(afFamily), 0, 0, []netlink.Attribute{
		{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdPfUnbind}},
	})
	if err != nil {
		return err
	}

	// binding to family
	_, err = nflog.setConfig(uint8(afFamily), seq, 0, []netlink.Attribute{
		{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdPfBind}},
	})
	if err != nil {
		return err
	}

	// binding to generic group
	_, err = nflog.setConfig(uint8(unix.AF_UNSPEC), seq, 0, []netlink.Attribute{
		{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdBind}},
	})
	if err != nil {
		return err
	}

	// binding to the requested group
	_, err = nflog.setConfig(uint8(unix.AF_UNSPEC), seq, uint16(group), []netlink.Attribute{
		{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdBind}},
	})
	if err != nil {
		return err
	}

	// set copy mode and buffer size
	data := append(nflog.bufsize, copyMode)
	data = append(data, 0x0)
	_, err = nflog.setConfig(uint8(unix.AF_UNSPEC), seq, uint16(group), []netlink.Attribute{
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
		_, err = nflog.setConfig(uint8(unix.AF_UNSPEC), seq, uint16(group), attrs)
		if err != nil {
			return err
		}
	}

	go func() {
		defer func() {
			// unbinding from group
			_, err = nflog.setConfig(uint8(unix.AF_UNSPEC), seq, uint16(group), []netlink.Attribute{
				{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdUnbind}},
			})
			if err != nil {
				// TODO: handle this error
				return
			}
		}()
		for {
			reply, err := nflog.Con.Receive()
			if err != nil {
				return
			}

			for _, msg := range reply {
				if msg.Header.Type == netlink.HeaderTypeDone {
					// this is the last message of a batch
					// continue to receive messages
					break
				}
				m, err := parseMsg(msg)
				if err != nil {
					fmt.Println(err)
					return
				}
				if ret := fn(m); ret != 0 {
					return
				}
			}
		}
	}()

	return nil
}

func putExtraHeader(familiy, version uint8, resid uint16) []byte {
	buf := make([]byte, 2)
	nlenc.PutUint16(buf, resid)
	return append([]byte{familiy, version}, buf...)
}

func (nflog *Nflog) setConfig(afFamily uint8, oseq uint32, resid uint16, attrs []netlink.Attribute) (uint32, error) {
	cmd, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return 0, err
	}
	data := putExtraHeader(afFamily, unix.NFNETLINK_V0, htonsU16(resid))
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
		errMsg, err := unmarschalErrMsg(msg.Data)
		if err != nil {
			return 0, err
		}
		seq = msg.Header.Sequence
		if errMsg.Code != 0 {
			return 0, fmt.Errorf("%#v", errMsg)
		}
	}

	return seq, nil
}

func htonsU16(i uint16) uint16 {
	buf := make([]byte, 2)
	nlenc.PutUint16(buf, i)
	return nlenc.Uint16(buf)
}

func htonsU32(i uint32) []byte {
	buf := make([]byte, 4)
	nlenc.PutUint32(buf, i)
	return buf
}

func parseMsg(msg netlink.Message) (Msg, error) {
	if msg.Header.Type&netlink.HeaderTypeError == netlink.HeaderTypeError {
		errMsg, err := unmarschalErrMsg(msg.Data)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%#v", errMsg)
	}
	m, err := extractAttributes(msg.Data)
	if err != nil {
		return nil, err
	}
	return m, nil
}
