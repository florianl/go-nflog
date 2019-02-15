//+build linux

package nflog

import (
	"bytes"
	"encoding/binary"
	"log"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func extractAttribute(m Msg, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case nfUlaAttrPacketHdr:
			m[AttrHwProtocol] = binary.BigEndian.Uint16(ad.Bytes()[:2])
			m[AttrHook] = ad.Bytes()[3]
		case nfUlaAttrMark:
			m[AttrMark] = ad.Uint32()
		case nfUlaAttrTimestamp:
			var sec, usec int64
			r := bytes.NewReader(ad.Bytes()[:8])
			if err := binary.Read(r, binary.BigEndian, &sec); err != nil {
				return err
			}
			r = bytes.NewReader(ad.Bytes()[8:])
			if err := binary.Read(r, binary.BigEndian, &usec); err != nil {
				return err
			}
			m[AttrTimestamp] = time.Unix(sec, usec*1000)
		case nfUlaAttrIfindexIndev:
			m[AttrIfindexIndev] = ad.Uint32()
		case nfUlaAttrIfindexOutdev:
			m[AttrIfindexOutdev] = ad.Uint32()
		case nfUlaAttrIfindexPhysIndev:
			m[AttrIfindexPhysIndev] = ad.Uint32()
		case nfUlaAttrIfindexPhysOutdev:
			m[AttrIfindexPhysOutdev] = ad.Uint32()
		case nfUlaAttrHwaddr:
			hwAddrLen := binary.BigEndian.Uint16(ad.Bytes()[:2])
			m[AttrHwAddr] = (ad.Bytes())[4 : 4+hwAddrLen]
		case nfUlaAttrPayload:
			m[AttrPayload] = ad.Bytes()
		case nfUlaAttrPrefix:
			m[AttrPrefix] = ad.String()
		case nfUlaAttrUID:
			m[AttrUID] = ad.Uint32()
		case nfUlaAttrSeq:
			m[AttrSeq] = ad.Uint32()
		case nfUlaAttrSeqGlobal:
			m[AttrSeqGlobal] = ad.Uint32()
		case nfUlaAttrGID:
			m[AttrGID] = ad.Uint32()
		case nfUlaAttrHwType:
			m[AttrHwType] = ad.Uint16()
		case nfUlaAttrHwHeader:
			m[AttrHwHeader] = ad.Bytes()
		case nfUlaAttrHwLen:
			m[AttrHwLen] = ad.Uint16()
		case nfUlaAttrCt + nlafNested:
			m[AttrCt] = ad.Bytes()
		case nfUlaAttrCtInfo:
			m[AttrCtInfo] = ad.Uint32()
		default:
			logger.Printf("Unknown attribute: %d %v\n", ad.Type(), ad.Bytes())
		}
	}

	return ad.Err()
}

func checkHeader(data []byte) int {
	if (data[0] == unix.AF_INET || data[0] == unix.AF_INET6) && data[1] == unix.NFNETLINK_V0 {
		return 4
	}
	return 0
}

func extractAttributes(logger *log.Logger, msg []byte) (Msg, error) {
	var data = make(Msg)

	offset := checkHeader(msg[:2])
	if err := extractAttribute(data, logger, msg[offset:]); err != nil {
		return nil, err
	}
	return data, nil
}
