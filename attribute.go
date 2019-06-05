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

func extractAttribute(a *Attribute, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = nativeEndian
	for ad.Next() {
		switch ad.Type() {
		case nfUlaAttrPacketHdr:
			hwProtocol := nativeEndian.Uint16(ad.Bytes()[:2])
			a.HwProtocol = &hwProtocol
			hook := uint8(ad.Bytes()[3])
			a.Hook = &hook
		case nfUlaAttrMark:
			mark := ad.Uint32()
			a.Mark = &mark
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
			timestamp := time.Unix(sec, usec*1000)
			a.Timestamp = &timestamp
		case nfUlaAttrIfindexIndev:
			inDev := ad.Uint32()
			a.InDev = &inDev
		case nfUlaAttrIfindexOutdev:
			outDev := ad.Uint32()
			a.OutDev = &outDev
		case nfUlaAttrIfindexPhysIndev:
			physInDev := ad.Uint32()
			a.PhysInDev = &physInDev
		case nfUlaAttrIfindexPhysOutdev:
			physOutDev := ad.Uint32()
			a.PhysOutDev = &physOutDev
		case nfUlaAttrHwaddr:
			hwAddrLen := binary.BigEndian.Uint16(ad.Bytes()[:2])
			hwAddr := (ad.Bytes())[4 : 4+hwAddrLen]
			a.HwAddr = &hwAddr
		case nfUlaAttrPayload:
			payload := ad.Bytes()
			a.Payload = &payload
		case nfUlaAttrPrefix:
			prefix := ad.String()
			a.Prefix = &prefix
		case nfUlaAttrUID:
			uid := ad.Uint32()
			a.UID = &uid
		case nfUlaAttrSeq:
			seq := ad.Uint32()
			a.Seq = &seq
		case nfUlaAttrSeqGlobal:
			seqGlobal := ad.Uint32()
			a.SeqGlobal = &seqGlobal
		case nfUlaAttrGID:
			gid := ad.Uint32()
			a.GID = &gid
		case nfUlaAttrHwType:
			hwType := ad.Uint16()
			a.HwType = &hwType
		case nfUlaAttrHwHeader:
			hwHeader := ad.Bytes()
			a.HwHeader = &hwHeader
		case nfUlaAttrHwLen:
			hwLen := ad.Uint16()
			a.HwLen = &hwLen
		case nfUlaAttrCt + nlafNested:
			ct := ad.Bytes()
			a.Ct = &ct
		case nfUlaAttrCtInfo:
			ctInfo := ad.Uint32()
			a.CtInfo = &ctInfo
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

func extractAttributes(logger *log.Logger, msg []byte) (Attribute, error) {
	attrs := Attribute{}

	offset := checkHeader(msg[:2])
	if err := extractAttribute(&attrs, logger, msg[offset:]); err != nil {
		return attrs, err
	}
	return attrs, nil
}
