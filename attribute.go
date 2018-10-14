//+build linux

package nflog

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Timestamp returns the timestamp of the message
func (m *Msg) Timestamp() (time.Time, error) {
	/*
		struct nfulnl_msg_packet_timestamp {
		__aligned_be64	sec;
		__aligned_be64	usec;
		};
	*/
	var sec, usec int64
	data := (*m)[NfUlaAttrTimestamp]
	if len(data) == 0 {
		return time.Unix(0, 0), ErrNoTimestamp
	}
	r := bytes.NewReader(data[:8])
	if err := binary.Read(r, binary.BigEndian, &sec); err != nil {
		return time.Unix(0, 0), err
	}
	r = bytes.NewReader(data[8:])
	if err := binary.Read(r, binary.BigEndian, &usec); err != nil {
		return time.Unix(0, 0), err
	}
	return time.Unix(sec, usec*1000), nil
}

func extractAttribute(m Msg, data []byte) error {
	attributes, err := netlink.UnmarshalAttributes(data)

	if err != nil {
		return err
	}

	for _, attr := range attributes {
		if int(attr.Type) >= attrMax || int(attr.Type) == attrUnspec {
			return ErrUnknownAttribute
		}
		m[int(attr.Type)] = attr.Data
	}
	return nil
}

func checkHeader(data []byte) int {
	if (data[0] == unix.AF_INET || data[0] == unix.AF_INET6) && data[1] == unix.NFNETLINK_V0 {
		return 4
	}
	return 0
}

func extractAttributes(msg []byte) (Msg, error) {
	var data = make(map[int][]byte)

	offset := checkHeader(msg[:2])
	if err := extractAttribute(data, msg[offset:]); err != nil {
		return nil, err
	}
	return data, nil
}
