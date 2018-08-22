//+build linux

package nflog

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

// Nflog represents a netfilter log handler
type Nflog struct {
	// Con is the pure representation of a netlink socket
	Con *netlink.Conn
}

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

	return &nflog, nil
}

// Close the connection to the conntrack subsystem
func (nflog *Nflog) Close() error {
	return nflog.Con.Close()
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
	cmd, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdPfUnbind}},
	})
	if err != nil {
		return err
	}
	data := putExtraHeader(uint8(afFamily), unix.NFNETLINK_V0, 0)
	data = append(data, cmd...)
	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((nfnlSubSysUlog << 8) | nfUlnlMsgConfig),
			Flags: netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge,
		},
		Data: data,
	}
	seq, err := nflog.execute(req)
	if err != nil {
		return err
	}

	// binding to family
	cmd, err = netlink.MarshalAttributes([]netlink.Attribute{
		{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdPfBind}},
	})
	if err != nil {
		return err
	}
	data = putExtraHeader(uint8(afFamily), unix.NFNETLINK_V0, 0)
	data = append(data, cmd...)
	req = netlink.Message{
		Header: netlink.Header{
			Type:     netlink.HeaderType((nfnlSubSysUlog << 8) | nfUlnlMsgConfig),
			Flags:    netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge,
			Sequence: seq,
		},
		Data: data,
	}
	if _, err := nflog.execute(req); err != nil {
		return err
	}

	// binding to the requested group
	cmd, err = netlink.MarshalAttributes([]netlink.Attribute{
		{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdBind}},
	})
	if err != nil {
		return err
	}
	data = putExtraHeader(uint8(unix.AF_UNSPEC), unix.NFNETLINK_V0, htons(uint16(group)))
	data = append(data, cmd...)
	req = netlink.Message{
		Header: netlink.Header{
			Type:     netlink.HeaderType((nfnlSubSysUlog << 8) | nfUlnlMsgConfig),
			Flags:    netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge,
			Sequence: seq,
		},
		Data: data,
	}
	if _, err := nflog.execute(req); err != nil {
		return err
	}

	// set copy mode
	cmd, err = netlink.MarshalAttributes([]netlink.Attribute{
		{Type: nfUlACfgMode, Data: []byte{0xff, 0xff, 0xff, 0xff, copyMode, 0x0}},
	})
	if err != nil {
		return err
	}
	data = putExtraHeader(uint8(unix.AF_UNSPEC), unix.NFNETLINK_V0, htons(uint16(group)))
	data = append(data, cmd...)
	req = netlink.Message{
		Header: netlink.Header{
			Type:     netlink.HeaderType((nfnlSubSysUlog << 8) | nfUlnlMsgConfig),
			Flags:    netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge,
			Sequence: seq,
		},
		Data: data,
	}
	if _, err := nflog.execute(req); err != nil {
		return err
	}

	// set flags
	cmd, err = netlink.MarshalAttributes([]netlink.Attribute{
		{Type: nfUlACfgFlags, Data: []byte{0x0, 0x3}},
	})
	if err != nil {
		return err
	}
	data = putExtraHeader(uint8(unix.AF_UNSPEC), unix.NFNETLINK_V0, htons(uint16(group)))
	data = append(data, cmd...)
	req = netlink.Message{
		Header: netlink.Header{
			Type:     netlink.HeaderType((nfnlSubSysUlog << 8) | nfUlnlMsgConfig),
			Flags:    netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge,
			Sequence: seq,
		},
		Data: data,
	}
	if _, err := nflog.execute(req); err != nil {
		return err
	}

	// set timeout
	cmd, err = netlink.MarshalAttributes([]netlink.Attribute{
		{Type: nfUlACfgTimeOut, Data: []byte{0x0, 0x0, 0x0, 0x7}},
	})
	if err != nil {
		return err
	}
	data = putExtraHeader(uint8(unix.AF_UNSPEC), unix.NFNETLINK_V0, htons(uint16(group)))
	data = append(data, cmd...)
	req = netlink.Message{
		Header: netlink.Header{
			Type:     netlink.HeaderType((nfnlSubSysUlog << 8) | nfUlnlMsgConfig),
			Flags:    netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge,
			Sequence: seq,
		},
		Data: data,
	}
	if _, err := nflog.execute(req); err != nil {
		return err
	}

	go func() {
		defer func() {
			// unbinding from group
			cmd, err = netlink.MarshalAttributes([]netlink.Attribute{
				{Type: nfUlACfgCmd, Data: []byte{nfUlnlCfgCmdUnbind}},
			})
			if err != nil {
				// TODO: handle this error
				return
			}
			data = putExtraHeader(uint8(afFamily), unix.NFNETLINK_V0, 0)
			data = append(data, cmd...)
			req = netlink.Message{
				Header: netlink.Header{
					Type:  netlink.HeaderType((nfnlSubSysUlog << 8) | nfUlnlMsgConfig),
					Flags: netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge,
				},
				Data: data,
			}
			if _, err := nflog.execute(req); err != nil {
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

func htons(i uint16) uint16 {
	buf := make([]byte, 2)
	nlenc.PutUint16(buf, i)
	return binary.BigEndian.Uint16(buf)
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
