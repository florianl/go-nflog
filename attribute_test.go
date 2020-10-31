//+build linux

package nflog

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
)

func pUint8(v uint8) *uint8 {
	return &v
}

func pUint16(v uint16) *uint16 {
	return &v
}

func pUint32(v uint32) *uint32 {
	return &v
}

func pString(v string) *string {
	return &v
}

func pBytes(v []byte) *[]byte {
	return &v
}

func pTime(sec, usec int64) *time.Time {
	t := time.Unix(sec, usec)
	return &t
}

func TestExtractAttributes(t *testing.T) {
	tests := map[string]struct {
		data []byte
		a    Attribute
	}{
		"SimplePing": {
			data: []byte{0x02, 0x00, 0x00, 0x64, 0x08, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x05, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x03, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x03, 0xe8, 0x08, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x03, 0xe8, 0x58, 0x00, 0x09, 0x00, 0x45, 0x00, 0x00, 0x54, 0x3d, 0x98, 0x40, 0x00, 0x40, 0x01, 0xf0, 0x52, 0x0a, 0x00, 0x00, 0xbd, 0x01, 0x01, 0x01, 0x01, 0x08, 0x00, 0xfe, 0x4b, 0x46, 0xd2, 0x00, 0x02, 0x4e, 0x01, 0x85, 0x5b, 0x00, 0x00, 0x00, 0x00, 0x1a, 0xb0, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37},
			a: Attribute{Hook: pUint8(0), Prefix: pString(""), HwProtocol: pUint16(unix.ETH_P_IP), UID: pUint32(0x03e8), GID: pUint32(0x03e8), OutDev: pUint32(0x03),
				Payload: pBytes([]byte{0x45, 0x00, 0x00, 0x54, 0x3d, 0x98, 0x40, 0x00, 0x40, 0x01, 0xf0, 0x52, 0x0a, 0x00, 0x00, 0xbd, 0x01, 0x01, 0x01, 0x01, 0x08, 0x00, 0xfe, 0x4b, 0x46, 0xd2, 0x00, 0x02, 0x4e, 0x01, 0x85, 0x5b, 0x00, 0x00, 0x00, 0x00, 0x1a, 0xb0, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37})},
		},
		"IPv6 TCP packet with conntrack data": {
			data: []byte{0x0a, 0x00, 0x00, 0x7b, 0x08, 0x00, 0x01, 0x00, 0x86, 0xdd, 0x01, 0x00, 0x11, 0x00, 0x0a, 0x00, 0x74, 0x65, 0x73, 0x74, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x3a, 0x20, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x10, 0x00, 0x08, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x1b, 0x21, 0x9f, 0x57, 0x31, 0x00, 0x00, 0x06, 0x00, 0x0f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x06, 0x00, 0x11, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x12, 0x00, 0x10, 0x00, 0xce, 0x7e, 0x7c, 0x41, 0x0f, 0xdb, 0x00, 0x1b, 0x21, 0x9f, 0x57, 0x31, 0x86, 0xdd, 0x00, 0x00, 0x14, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5f, 0x9d, 0x2f, 0x3a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x64, 0x04, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x21, 0x08, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x21, 0xe4, 0x00, 0x12, 0x80, 0x4c, 0x00, 0x01, 0x80, 0x2c, 0x00, 0x01, 0x80, 0x14, 0x00, 0x03, 0x00, 0x20, 0x01, 0x04, 0x70, 0xb7, 0x50, 0x00, 0x01, 0xf5, 0x18, 0x96, 0xf6, 0xe8, 0xae, 0x07, 0x2d, 0x14, 0x00, 0x04, 0x00, 0x2a, 0x07, 0x57, 0x41, 0x00, 0x00, 0x11, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x1c, 0x00, 0x02, 0x80, 0x05, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00, 0xfe, 0x0f, 0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0x01, 0xbb, 0x00, 0x00, 0x4c, 0x00, 0x02, 0x80, 0x2c, 0x00, 0x01, 0x80, 0x14, 0x00, 0x03, 0x00, 0x2a, 0x07, 0x57, 0x41, 0x00, 0x00, 0x11, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x14, 0x00, 0x04, 0x00, 0x20, 0x01, 0x04, 0x70, 0xb7, 0x50, 0x00, 0x01, 0xf5, 0x18, 0x96, 0xf6, 0xe8, 0xae, 0x07, 0x2d, 0x1c, 0x00, 0x02, 0x80, 0x05, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00, 0x01, 0xbb, 0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0xfe, 0x0f, 0x00, 0x00, 0x08, 0x00, 0x0c, 0x00, 0x18, 0x9d, 0x23, 0xd6, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x08, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01, 0x2c, 0x30, 0x00, 0x04, 0x80, 0x2c, 0x00, 0x01, 0x80, 0x05, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x06, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x07, 0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x06, 0x00, 0x05, 0x00, 0x33, 0x00, 0x00, 0x00, 0x08, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x09, 0x00, 0x60, 0x0e, 0xb3, 0xfe, 0x00, 0x20, 0x06, 0x37, 0x20, 0x01, 0x04, 0x70, 0xb7, 0x50, 0x00, 0x01, 0xf5, 0x18, 0x96, 0xf6, 0xe8, 0xae, 0x07, 0x2d, 0x2a, 0x07, 0x57, 0x41, 0x00, 0x00, 0x11, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x0f, 0x01, 0xbb, 0x74, 0xde, 0x6b, 0xcb, 0x4a, 0xf3, 0x26, 0xdc, 0x80, 0x10, 0x07, 0xdc, 0x0b, 0xfa, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x4d, 0xcd, 0xeb, 0x52, 0x87, 0x98, 0x65, 0x7b},
			a: Attribute{
				Hook: pUint8(0), Prefix: pString("testprefix: "), HwProtocol: pUint16(unix.ETH_P_IPV6), UID: pUint32(33), GID: pUint32(33), InDev: pUint32(0x02),
				Timestamp: pTime(1604136762, 156676000), HwType: pUint16(1), HwLen: pUint16(14),
				HwAddr:   pBytes([]byte{0x00, 0x1b, 0x21, 0x9f, 0x57, 0x31}),
				HwHeader: pBytes([]byte{0xce, 0x7e, 0x7c, 0x41, 0x0f, 0xdb, 0x00, 0x1b, 0x21, 0x9f, 0x57, 0x31, 0x86, 0xdd}),
				CtInfo:   pUint32(0),
				Ct:       pBytes([]byte{0x4c, 0x00, 0x01, 0x80, 0x2c, 0x00, 0x01, 0x80, 0x14, 0x00, 0x03, 0x00, 0x20, 0x01, 0x04, 0x70, 0xb7, 0x50, 0x00, 0x01, 0xf5, 0x18, 0x96, 0xf6, 0xe8, 0xae, 0x07, 0x2d, 0x14, 0x00, 0x04, 0x00, 0x2a, 0x07, 0x57, 0x41, 0x00, 0x00, 0x11, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x1c, 0x00, 0x02, 0x80, 0x05, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00, 0xfe, 0x0f, 0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0x01, 0xbb, 0x00, 0x00, 0x4c, 0x00, 0x02, 0x80, 0x2c, 0x00, 0x01, 0x80, 0x14, 0x00, 0x03, 0x00, 0x2a, 0x07, 0x57, 0x41, 0x00, 0x00, 0x11, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x14, 0x00, 0x04, 0x00, 0x20, 0x01, 0x04, 0x70, 0xb7, 0x50, 0x00, 0x01, 0xf5, 0x18, 0x96, 0xf6, 0xe8, 0xae, 0x07, 0x2d, 0x1c, 0x00, 0x02, 0x80, 0x05, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00, 0x01, 0xbb, 0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0xfe, 0x0f, 0x00, 0x00, 0x08, 0x00, 0x0c, 0x00, 0x18, 0x9d, 0x23, 0xd6, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x08, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01, 0x2c, 0x30, 0x00, 0x04, 0x80, 0x2c, 0x00, 0x01, 0x80, 0x05, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x06, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x07, 0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x06, 0x00, 0x05, 0x00, 0x33, 0x00, 0x00, 0x00}),
				Payload:  pBytes([]byte{0x60, 0x0e, 0xb3, 0xfe, 0x00, 0x20, 0x06, 0x37, 0x20, 0x01, 0x04, 0x70, 0xb7, 0x50, 0x00, 0x01, 0xf5, 0x18, 0x96, 0xf6, 0xe8, 0xae, 0x07, 0x2d, 0x2a, 0x07, 0x57, 0x41, 0x00, 0x00, 0x11, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x0f, 0x01, 0xbb, 0x74, 0xde, 0x6b, 0xcb, 0x4a, 0xf3, 0x26, 0xdc, 0x80, 0x10, 0x07, 0xdc, 0x0b, 0xfa, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x4d, 0xcd, 0xeb, 0x52, 0x87, 0x98, 0x65, 0x7b}),
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			a, err := extractAttributes(nil, tc.data)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.a, a); diff != "" {
				t.Fatalf("unexpected number of request messages (-want +got):\n%s", diff)
			}
		})

	}

}
