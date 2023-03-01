package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"testing"

	"github.com/arailly/mytls12/record"
	"github.com/arailly/mytls12/util"
	"github.com/google/go-cmp/cmp"
)

func TestFinished(t *testing.T) {
	encryptedPreMasterSecret := []byte{
		0x0a, 0x11, 0xb2, 0xeb, 0xa2, 0xda, 0xc5, 0x1f,
		0x01, 0xaa, 0x3d, 0xea, 0xcb, 0x57, 0xe2, 0x2e,
		0x30, 0x62, 0x92, 0xbe, 0x9a, 0x0b, 0x52, 0x7e,
		0xd2, 0x96, 0x51, 0x21, 0x1c, 0x10, 0xad, 0x72,
		0xc1, 0x13, 0xc0, 0xec, 0x3d, 0xbf, 0xb8, 0xcd,
		0x8e, 0xab, 0xba, 0x65, 0xac, 0xb6, 0x22, 0x4a,
		0xdf, 0x07, 0x3c, 0x9e, 0x9b, 0x6a, 0xe8, 0x24,
		0x44, 0x03, 0x8a, 0xb3, 0xcb, 0xaf, 0x9c, 0x59,
		0xf1, 0x3f, 0xc5, 0xed, 0x3e, 0x73, 0xea, 0x9c,
		0x7c, 0x5f, 0x89, 0x04, 0x66, 0xf9, 0x76, 0x04,
		0x00, 0xde, 0x28, 0xaa, 0x9a, 0xbe, 0xa8, 0xc6,
		0x3d, 0x68, 0x69, 0x09, 0x27, 0xd5, 0x66, 0x3e,
		0x25, 0x89, 0xb8, 0xc8, 0x36, 0xf5, 0x49, 0xb7,
		0x28, 0xde, 0xf0, 0x09, 0x7b, 0x1e, 0xb1, 0x41,
		0x2c, 0xb9, 0x8c, 0xcf, 0xd6, 0x41, 0xbe, 0xb2,
		0x5c, 0x47, 0xcd, 0x6f, 0x54, 0xb7, 0x3f, 0x16,
		0x43, 0x9e, 0xb1, 0xa0, 0xe7, 0x4d, 0x3e, 0xcb,
		0x74, 0x77, 0x24, 0x33, 0xa6, 0x85, 0x6c, 0x1b,
		0x92, 0x5a, 0xe9, 0x82, 0x86, 0xdd, 0x0d, 0xe8,
		0x85, 0x9d, 0xa8, 0xd2, 0xaa, 0x9a, 0xdb, 0x54,
		0xe6, 0xb3, 0xe6, 0xf2, 0x74, 0x5a, 0x63, 0xac,
		0xd4, 0xf1, 0x54, 0xc3, 0x9a, 0x6e, 0x08, 0x91,
		0x1f, 0xe4, 0x54, 0xf3, 0x58, 0xc2, 0x79, 0xef,
		0xf0, 0x12, 0xc2, 0x92, 0x0c, 0x24, 0xfb, 0xc9,
		0x4a, 0x28, 0x66, 0xff, 0x04, 0xfa, 0xf7, 0x2f,
		0x9f, 0x1a, 0x43, 0x5a, 0xe9, 0x73, 0xac, 0xa8,
		0xd4, 0x1e, 0xe8, 0x32, 0xa9, 0x38, 0xcc, 0x84,
		0x2a, 0x66, 0x61, 0x85, 0x1b, 0xb1, 0x3e, 0xf7,
		0xcb, 0x9c, 0x26, 0x66, 0x2f, 0xb9, 0x9d, 0xaf,
		0x52, 0xb2, 0x21, 0xb3, 0x45, 0xc1, 0x74, 0xdb,
		0x1c, 0x44, 0x55, 0x6a, 0x87, 0x78, 0x44, 0x79,
		0xdc, 0xf6, 0x8e, 0xe9, 0x41, 0x7f, 0xe2, 0x1c,
	}
	clientRandom := []byte{
		0x70, 0x0d, 0x1d, 0xcb, 0xd8, 0x74, 0x10, 0x93,
		0x87, 0xaf, 0xad, 0xcc, 0x7a, 0x4d, 0x86, 0xba,
		0x56, 0xd1, 0xf0, 0x32, 0x9b, 0x56, 0xcf, 0xe1,
		0xcb, 0x14, 0x38, 0x48, 0x15, 0x29, 0x91, 0x92,
	}
	serverRandom := []byte{
		0x31, 0xe4, 0xa4, 0xca, 0x1b, 0xc1, 0xee, 0xe3,
		0xbc, 0xb1, 0x37, 0x8e, 0xac, 0x1d, 0x7b, 0x1b,
		0x1c, 0xbe, 0x23, 0xc7, 0x17, 0xed, 0x7e, 0xe8,
		0x91, 0x96, 0x06, 0x61, 0x5e, 0xf9, 0x7c, 0x98,
	}
	handshakeMessages := []byte{
		//client hello
		0x01, 0x00, 0x00, 0xa8, 0x03, 0x03, 0x70, 0x0d,
		0x1d, 0xcb, 0xd8, 0x74, 0x10, 0x93, 0x87, 0xaf,
		0xad, 0xcc, 0x7a, 0x4d, 0x86, 0xba, 0x56, 0xd1,
		0xf0, 0x32, 0x9b, 0x56, 0xcf, 0xe1, 0xcb, 0x14,
		0x38, 0x48, 0x15, 0x29, 0x91, 0x92, 0x20, 0x84,
		0xc3, 0x15, 0x84, 0xaa, 0xc5, 0xd9, 0x61, 0x5a,
		0xf7, 0x31, 0x7c, 0xa2, 0xc4, 0xb3, 0x0c, 0xe4,
		0x59, 0x50, 0xb5, 0x77, 0x39, 0xa4, 0xfe, 0xed,
		0x8a, 0xf1, 0x44, 0xb9, 0xb7, 0x06, 0x0d, 0x00,
		0x02, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x5d, 0x00,
		0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00, 0x09,
		0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73,
		0x74, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08,
		0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,
		0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0d,
		0x00, 0x1a, 0x00, 0x18, 0x08, 0x04, 0x04, 0x03,
		0x08, 0x07, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01,
		0x05, 0x01, 0x06, 0x01, 0x05, 0x03, 0x06, 0x03,
		0x02, 0x01, 0x02, 0x03, 0xff, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x2b, 0x00,
		0x03, 0x02, 0x03, 0x03,
		//server hello
		0x02, 0x00, 0x00, 0x33, 0x03, 0x03, 0x31, 0xe4,
		0xa4, 0xca, 0x1b, 0xc1, 0xee, 0xe3, 0xbc, 0xb1,
		0x37, 0x8e, 0xac, 0x1d, 0x7b, 0x1b, 0x1c, 0xbe,
		0x23, 0xc7, 0x17, 0xed, 0x7e, 0xe8, 0x91, 0x96,
		0x06, 0x61, 0x5e, 0xf9, 0x7c, 0x98, 0x00, 0x00,
		0x2f, 0x00, 0x00, 0x0b, 0xff, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
		// certificates
		0x0b, 0x00, 0x04, 0x1e, 0x00, 0x04, 0x1b, 0x00,
		0x04, 0x18, 0x30, 0x82, 0x04, 0x14, 0x30, 0x82,
		0x02, 0xfc, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
		0x14, 0x5f, 0x97, 0x3e, 0x2a, 0x61, 0xe7, 0x6e,
		0xb4, 0x7f, 0xdf, 0x08, 0xda, 0x5a, 0x86, 0x84,
		0x19, 0xa1, 0x9b, 0x30, 0x0f, 0x30, 0x0d, 0x06,
		0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
		0x01, 0x0b, 0x05, 0x00, 0x30, 0x77, 0x31, 0x0b,
		0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
		0x02, 0x43, 0x41, 0x31, 0x10, 0x30, 0x0e, 0x06,
		0x03, 0x55, 0x04, 0x08, 0x13, 0x07, 0x54, 0x6f,
		0x72, 0x6f, 0x6e, 0x74, 0x6f, 0x31, 0x0b, 0x30,
		0x09, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x02,
		0x4f, 0x4e, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03,
		0x55, 0x04, 0x0a, 0x13, 0x12, 0x4d, 0x79, 0x20,
		0x41, 0x77, 0x65, 0x73, 0x6f, 0x6d, 0x65, 0x20,
		0x43, 0x6f, 0x6d, 0x70, 0x61, 0x6e, 0x79, 0x31,
		0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0b,
		0x13, 0x0b, 0x43, 0x41, 0x20, 0x53, 0x65, 0x72,
		0x76, 0x69, 0x63, 0x65, 0x73, 0x31, 0x16, 0x30,
		0x14, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0d,
		0x4d, 0x79, 0x20, 0x41, 0x77, 0x65, 0x73, 0x6f,
		0x6d, 0x65, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17,
		0x0d, 0x32, 0x32, 0x31, 0x32, 0x31, 0x33, 0x30,
		0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d,
		0x32, 0x33, 0x31, 0x32, 0x31, 0x33, 0x30, 0x30,
		0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x7c, 0x31,
		0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
		0x13, 0x02, 0x43, 0x41, 0x31, 0x10, 0x30, 0x0e,
		0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x07, 0x54,
		0x6f, 0x72, 0x6f, 0x6e, 0x74, 0x6f, 0x31, 0x0b,
		0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13,
		0x02, 0x4f, 0x4e, 0x31, 0x1b, 0x30, 0x19, 0x06,
		0x03, 0x55, 0x04, 0x0a, 0x13, 0x12, 0x4d, 0x79,
		0x20, 0x41, 0x77, 0x65, 0x73, 0x6f, 0x6d, 0x65,
		0x20, 0x43, 0x6f, 0x6d, 0x70, 0x61, 0x6e, 0x79,
		0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04,
		0x0b, 0x13, 0x14, 0x44, 0x69, 0x73, 0x74, 0x72,
		0x69, 0x62, 0x75, 0x74, 0x65, 0x64, 0x20, 0x53,
		0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x31,
		0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03,
		0x13, 0x09, 0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e,
		0x30, 0x2e, 0x31, 0x30, 0x82, 0x01, 0x22, 0x30,
		0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
		0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82,
		0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02,
		0x82, 0x01, 0x01, 0x00, 0xc5, 0xd5, 0x62, 0x93,
		0x9c, 0x1d, 0x29, 0x74, 0xfe, 0xa1, 0x5e, 0x38,
		0x69, 0xbd, 0x93, 0xf1, 0x77, 0x75, 0xe6, 0x69,
		0xdf, 0x1f, 0x8c, 0x6d, 0xdc, 0x05, 0x3f, 0x8d,
		0xa1, 0x22, 0xab, 0x1b, 0x0b, 0x50, 0xc4, 0x78,
		0x95, 0x21, 0x32, 0x56, 0x6c, 0x24, 0x03, 0x97,
		0x20, 0x3d, 0x03, 0x0e, 0x24, 0xa6, 0x4f, 0x2d,
		0xe0, 0x1c, 0xb0, 0x42, 0xa1, 0xec, 0x17, 0x37,
		0x50, 0x68, 0xfb, 0x69, 0x3d, 0xd9, 0x9d, 0x10,
		0xa9, 0x9c, 0x39, 0xe6, 0xdc, 0x4e, 0x63, 0xd0,
		0xa5, 0xb6, 0x96, 0xf3, 0x2f, 0xfc, 0x96, 0xfd,
		0x47, 0xa2, 0x19, 0xe1, 0x2c, 0x2b, 0xb2, 0x9a,
		0xa2, 0x7f, 0x29, 0x7c, 0x14, 0x5a, 0x9a, 0x16,
		0x88, 0x38, 0x98, 0xc8, 0x1b, 0xa6, 0x4d, 0xc5,
		0x23, 0x96, 0x6e, 0xa2, 0x09, 0x70, 0x76, 0x7b,
		0x8b, 0x8f, 0x12, 0x6b, 0xfa, 0x58, 0xc2, 0x4a,
		0x63, 0x32, 0xb6, 0xc0, 0x22, 0x49, 0x08, 0x70,
		0xb1, 0x05, 0xf5, 0x55, 0x3e, 0x5f, 0xe2, 0xdf,
		0x0a, 0x01, 0x2b, 0x2a, 0x67, 0x76, 0xe2, 0xc6,
		0x94, 0xac, 0xdc, 0x29, 0x5c, 0x13, 0x6a, 0xbe,
		0xe7, 0x3d, 0x6c, 0xfe, 0x90, 0xfe, 0xd1, 0xa1,
		0xc0, 0x61, 0x04, 0x1a, 0xdb, 0x43, 0x8f, 0x4d,
		0xb4, 0xd6, 0x07, 0x6c, 0xb6, 0x50, 0xb1, 0x76,
		0xa7, 0x05, 0x1d, 0x1c, 0x68, 0x53, 0x7e, 0x54,
		0x72, 0xa2, 0x98, 0xf5, 0x1f, 0x32, 0x16, 0x7b,
		0xef, 0x79, 0x7b, 0x2a, 0x77, 0x31, 0x52, 0xd4,
		0x64, 0x96, 0x74, 0xcd, 0x3f, 0x61, 0x58, 0x67,
		0xbc, 0x22, 0xcc, 0xca, 0xa3, 0x4f, 0xaf, 0x9c,
		0x24, 0x29, 0x2b, 0x14, 0x3a, 0xa3, 0xfa, 0xe7,
		0xbd, 0xd6, 0xee, 0x45, 0x1a, 0x52, 0x7d, 0x8d,
		0xac, 0xcf, 0x8a, 0xf4, 0x5a, 0x16, 0x3d, 0xe1,
		0x64, 0xa9, 0x14, 0x3e, 0x8f, 0xa3, 0x97, 0x49,
		0x32, 0xd8, 0x32, 0xd5, 0x02, 0x03, 0x01, 0x00,
		0x01, 0xa3, 0x81, 0x92, 0x30, 0x81, 0x8f, 0x30,
		0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01,
		0xff, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30,
		0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c,
		0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
		0x05, 0x07, 0x03, 0x01, 0x30, 0x0c, 0x06, 0x03,
		0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02,
		0x30, 0x00, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
		0x0e, 0x04, 0x16, 0x04, 0x14, 0x6e, 0x0c, 0xb8,
		0x30, 0x98, 0x71, 0xe8, 0xf0, 0xda, 0x52, 0x2f,
		0x70, 0x2c, 0x43, 0xb8, 0xae, 0x67, 0xd8, 0x81,
		0xa1, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23,
		0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x1f, 0x52,
		0xa7, 0x90, 0x78, 0x0d, 0x79, 0xb3, 0x20, 0x66,
		0x81, 0x16, 0x8c, 0x01, 0x17, 0x6a, 0xe7, 0x58,
		0x5f, 0x88, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x1d,
		0x11, 0x04, 0x13, 0x30, 0x11, 0x82, 0x09, 0x6c,
		0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
		0x87, 0x04, 0x7f, 0x00, 0x00, 0x01, 0x30, 0x0d,
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
		0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01,
		0x01, 0x00, 0x9a, 0xfb, 0x4e, 0x7e, 0x12, 0x87,
		0x50, 0xb8, 0x73, 0xbe, 0xfe, 0xb3, 0x66, 0x7e,
		0x97, 0xcb, 0x4a, 0x73, 0x16, 0x0d, 0xbf, 0xe6,
		0x4d, 0x14, 0x3d, 0xb3, 0xb3, 0x74, 0xa0, 0xe0,
		0x0d, 0x9e, 0x30, 0xda, 0x92, 0xcb, 0xe4, 0x96,
		0xf9, 0x9c, 0xb0, 0xbf, 0xa8, 0x3f, 0xdf, 0x4a,
		0x80, 0xc5, 0xed, 0xf6, 0xbf, 0x26, 0x32, 0x99,
		0x82, 0x99, 0xa4, 0x02, 0x64, 0xc3, 0x0c, 0x1d,
		0xd8, 0xa0, 0x8c, 0x9b, 0x5c, 0x34, 0x9b, 0x7c,
		0x10, 0xf4, 0x9c, 0x02, 0x4e, 0xcb, 0x27, 0x43,
		0x40, 0xcc, 0x04, 0xec, 0xe2, 0x0a, 0x4f, 0xb5,
		0x1b, 0xd1, 0x08, 0xd3, 0x56, 0xb7, 0x10, 0xa2,
		0xe0, 0xb8, 0xfb, 0x68, 0xb8, 0xfe, 0xff, 0x7a,
		0xb4, 0xc4, 0x1a, 0xe0, 0x92, 0x0b, 0x16, 0x97,
		0xb5, 0x10, 0x5e, 0x75, 0xe7, 0x2e, 0x77, 0x1f,
		0xae, 0x42, 0x25, 0xaa, 0xbc, 0xeb, 0x80, 0x8f,
		0xc0, 0xf9, 0xc5, 0xa7, 0x67, 0x14, 0x97, 0x16,
		0xa6, 0xb9, 0x5a, 0xe8, 0xeb, 0xad, 0xa5, 0xc3,
		0xe2, 0x68, 0x3c, 0x62, 0xeb, 0xf6, 0x0d, 0x54,
		0x46, 0x6d, 0xb9, 0x86, 0xfb, 0x96, 0xb8, 0x09,
		0xb0, 0x8f, 0xa2, 0x18, 0xaf, 0xbe, 0x86, 0x08,
		0xd8, 0x2e, 0x10, 0x30, 0x7d, 0x54, 0x6a, 0x40,
		0x00, 0x53, 0xeb, 0x2a, 0xdd, 0x94, 0xf1, 0x52,
		0x17, 0x0d, 0xac, 0x69, 0xd3, 0x31, 0x29, 0x29,
		0x76, 0xe9, 0xf1, 0x60, 0xf0, 0xf0, 0x78, 0x28,
		0x60, 0xae, 0xc5, 0xce, 0xfc, 0x70, 0xf6, 0xf6,
		0x7f, 0x23, 0x47, 0x61, 0xcd, 0xe8, 0x4a, 0x0a,
		0x73, 0xc5, 0x98, 0x6c, 0x15, 0x23, 0x99, 0x45,
		0xd4, 0x8f, 0xe6, 0xb8, 0x90, 0x37, 0xeb, 0xf3,
		0x4f, 0xaf, 0x95, 0x22, 0x1e, 0x2a, 0xa4, 0x09,
		0xec, 0x7c, 0x72, 0x16, 0x9d, 0x42, 0xbd, 0x48,
		0xec, 0x5e, 0x43, 0x5c, 0x20, 0x4a, 0xd0, 0xdf,
		0x79, 0x06,
		// server hello done
		0x0e, 0x00, 0x00, 0x00,
		// client key exchange
		0x10, 0x00, 0x01, 0x02, 0x01, 0x00, 0x0a, 0x11,
		0xb2, 0xeb, 0xa2, 0xda, 0xc5, 0x1f, 0x01, 0xaa,
		0x3d, 0xea, 0xcb, 0x57, 0xe2, 0x2e, 0x30, 0x62,
		0x92, 0xbe, 0x9a, 0x0b, 0x52, 0x7e, 0xd2, 0x96,
		0x51, 0x21, 0x1c, 0x10, 0xad, 0x72, 0xc1, 0x13,
		0xc0, 0xec, 0x3d, 0xbf, 0xb8, 0xcd, 0x8e, 0xab,
		0xba, 0x65, 0xac, 0xb6, 0x22, 0x4a, 0xdf, 0x07,
		0x3c, 0x9e, 0x9b, 0x6a, 0xe8, 0x24, 0x44, 0x03,
		0x8a, 0xb3, 0xcb, 0xaf, 0x9c, 0x59, 0xf1, 0x3f,
		0xc5, 0xed, 0x3e, 0x73, 0xea, 0x9c, 0x7c, 0x5f,
		0x89, 0x04, 0x66, 0xf9, 0x76, 0x04, 0x00, 0xde,
		0x28, 0xaa, 0x9a, 0xbe, 0xa8, 0xc6, 0x3d, 0x68,
		0x69, 0x09, 0x27, 0xd5, 0x66, 0x3e, 0x25, 0x89,
		0xb8, 0xc8, 0x36, 0xf5, 0x49, 0xb7, 0x28, 0xde,
		0xf0, 0x09, 0x7b, 0x1e, 0xb1, 0x41, 0x2c, 0xb9,
		0x8c, 0xcf, 0xd6, 0x41, 0xbe, 0xb2, 0x5c, 0x47,
		0xcd, 0x6f, 0x54, 0xb7, 0x3f, 0x16, 0x43, 0x9e,
		0xb1, 0xa0, 0xe7, 0x4d, 0x3e, 0xcb, 0x74, 0x77,
		0x24, 0x33, 0xa6, 0x85, 0x6c, 0x1b, 0x92, 0x5a,
		0xe9, 0x82, 0x86, 0xdd, 0x0d, 0xe8, 0x85, 0x9d,
		0xa8, 0xd2, 0xaa, 0x9a, 0xdb, 0x54, 0xe6, 0xb3,
		0xe6, 0xf2, 0x74, 0x5a, 0x63, 0xac, 0xd4, 0xf1,
		0x54, 0xc3, 0x9a, 0x6e, 0x08, 0x91, 0x1f, 0xe4,
		0x54, 0xf3, 0x58, 0xc2, 0x79, 0xef, 0xf0, 0x12,
		0xc2, 0x92, 0x0c, 0x24, 0xfb, 0xc9, 0x4a, 0x28,
		0x66, 0xff, 0x04, 0xfa, 0xf7, 0x2f, 0x9f, 0x1a,
		0x43, 0x5a, 0xe9, 0x73, 0xac, 0xa8, 0xd4, 0x1e,
		0xe8, 0x32, 0xa9, 0x38, 0xcc, 0x84, 0x2a, 0x66,
		0x61, 0x85, 0x1b, 0xb1, 0x3e, 0xf7, 0xcb, 0x9c,
		0x26, 0x66, 0x2f, 0xb9, 0x9d, 0xaf, 0x52, 0xb2,
		0x21, 0xb3, 0x45, 0xc1, 0x74, 0xdb, 0x1c, 0x44,
		0x55, 0x6a, 0x87, 0x78, 0x44, 0x79, 0xdc, 0xf6,
		0x8e, 0xe9, 0x41, 0x7f, 0xe2, 0x1c,
	}
	rng := rand.Reader
	privKey := GetPrivateKey(t)
	preMasterSecret, err := rsa.DecryptPKCS1v15(rng, privKey, encryptedPreMasterSecret)
	if err != nil {
		t.Fatal(err)
	}
	masterSecret := record.CalcMasterSecret(preMasterSecret, clientRandom, serverRandom)
	verifyData := CalcClientVerifyData(masterSecret, handshakeMessages)
	if len(verifyData) != 12 {
		t.Error(len(verifyData))
	}
	expectedVerifyData := []byte{
		0x58, 0xc3, 0xf0, 0x30, 0x2b, 0xb7, 0xab, 0x8a,
		0x9b, 0x11, 0xdf, 0x80,
	}
	if diff := cmp.Diff(expectedVerifyData, verifyData); diff != "" {
		t.Error(diff)
	}
}

func TestCipher(t *testing.T) {
	encryptedPreMasterSecret := []byte{
		0x3b, 0xce, 0x5a, 0x87, 0x2c, 0xc6, 0x46, 0xb8,
		0x4f, 0x5b, 0x1a, 0x27, 0xb7, 0x2e, 0xca, 0xfe,
		0xc9, 0x12, 0xcc, 0xea, 0xe6, 0xe2, 0x58, 0x78,
		0x3a, 0x2a, 0x06, 0x56, 0x2a, 0x29, 0xa3, 0x15,
		0xcf, 0x8a, 0xeb, 0x68, 0x55, 0x84, 0x28, 0xd9,
		0xea, 0x34, 0x93, 0x30, 0xdd, 0xf7, 0x00, 0x47,
		0xeb, 0x32, 0x4b, 0x80, 0x5d, 0xf3, 0x0a, 0xde,
		0xe2, 0x95, 0x24, 0xc4, 0xe0, 0x03, 0x2c, 0xdc,
		0x2b, 0xfe, 0x20, 0x84, 0x78, 0xcd, 0xf3, 0xa1,
		0xb1, 0xbc, 0x63, 0x77, 0x48, 0x55, 0x3d, 0xaa,
		0x6b, 0xa3, 0xa8, 0xd4, 0x40, 0x68, 0xfd, 0x5d,
		0x43, 0xb6, 0x9a, 0xa4, 0xce, 0x11, 0x5d, 0x9f,
		0x1b, 0x4f, 0xa3, 0x43, 0x28, 0x9d, 0xc2, 0xd0,
		0xb5, 0x09, 0x0f, 0x49, 0xaf, 0x86, 0xf4, 0xb8,
		0x2f, 0x7e, 0xc7, 0x0c, 0xb6, 0x35, 0x17, 0x29,
		0xa9, 0xfd, 0xac, 0xba, 0x52, 0xa3, 0xb3, 0x41,
		0xe5, 0xf9, 0xb3, 0xa4, 0x05, 0xfc, 0x8f, 0x7f,
		0x5e, 0xf4, 0xe6, 0x85, 0xef, 0x3e, 0xe8, 0x66,
		0xeb, 0xb4, 0x7b, 0x04, 0xaf, 0xe7, 0x86, 0x76,
		0x8b, 0xbd, 0x98, 0x74, 0x0b, 0xd0, 0x1d, 0xfa,
		0xaa, 0x68, 0x20, 0xf7, 0xc9, 0xc6, 0x4a, 0x17,
		0xd2, 0xe5, 0x4d, 0x3e, 0xfa, 0x7e, 0x44, 0x6a,
		0x08, 0x68, 0xd6, 0x81, 0xa8, 0xbb, 0x8d, 0x22,
		0x06, 0x64, 0xb7, 0xf2, 0x7a, 0x4c, 0xb2, 0x39,
		0x17, 0x8e, 0x84, 0x0f, 0xb4, 0x11, 0xd9, 0xb1,
		0x2b, 0xfb, 0xad, 0xbd, 0x73, 0x7c, 0x65, 0xd8,
		0x65, 0x19, 0x8c, 0xeb, 0x02, 0x97, 0x58, 0xe0,
		0xce, 0x04, 0x13, 0x01, 0xcf, 0xa5, 0xe4, 0x4b,
		0xe0, 0x71, 0x68, 0xa1, 0xcd, 0x15, 0xfe, 0x41,
		0x8e, 0x37, 0x9f, 0x75, 0xc7, 0xeb, 0xc0, 0x9d,
		0xd9, 0x2d, 0xa7, 0x09, 0xce, 0x8e, 0x44, 0x36,
		0x99, 0x75, 0xd9, 0x99, 0x0c, 0xe1, 0x3c, 0x97,
	}
	clientRandom := []byte{
		0x61, 0x7b, 0x6f, 0x34, 0x9f, 0x99, 0x45, 0xfe,
		0x09, 0xb8, 0xa7, 0xf9, 0x21, 0x2a, 0xb3, 0xca,
		0x45, 0xbd, 0x51, 0x2a, 0x81, 0xab, 0xad, 0x32,
		0xb0, 0x96, 0x65, 0xed, 0x54, 0xed, 0x54, 0xa6,
	}
	serverRandom := []byte{
		0x16, 0xb5, 0xfd, 0xde, 0xcc, 0x01, 0xa3, 0xc1,
		0xc4, 0x5c, 0x90, 0x38, 0x50, 0xe3, 0x6f, 0x99,
		0x03, 0xcd, 0xf9, 0xc9, 0xbe, 0xe7, 0x56, 0x7e,
		0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01,
	}
	verifyData := []byte{
		0x67, 0x1d, 0x8f, 0x60, 0x05, 0xfb, 0xb8, 0x58,
		0x9b, 0xef, 0x2c, 0xfc,
	}
	iv := []byte{
		0x69, 0x7e, 0x0a,
		0x72, 0x19, 0xc6, 0x85, 0x0a, 0x73, 0xad, 0xc4,
		0xe6, 0x6e, 0x67, 0xd4, 0xd5,
	}
	rng := rand.Reader
	privKey := GetPrivateKey(t)
	preMasterSecret, err := rsa.DecryptPKCS1v15(rng, privKey, encryptedPreMasterSecret)
	if err != nil {
		t.Fatal(err)
	}
	masterSecret := record.CalcMasterSecret(preMasterSecret, clientRandom, serverRandom)
	keyBlock := record.CalcKeyBlock(masterSecret, serverRandom, clientRandom, 20*2+16*2)
	clientWriteMACKey := keyBlock[:20]
	clientWriteKey := keyBlock[40:56]

	handshake := util.ToBytes(NewHandshake(
		HandshakeTypeFinished,
		util.ToBytes(verifyData),
	))
	mac := hmac.New(sha1.New, clientWriteMACKey)
	macSeed := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x16, 0x03, 0x03, 0x00, 0x10,
	}
	macSeed = append(macSeed, handshake...)
	mac.Write(macSeed)
	plaintext := append(handshake, mac.Sum(nil)...) // 16 + 20
	paddingWithLength := []byte{
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b,
	}
	plaintext = append(plaintext, paddingWithLength...)

	block, err := aes.NewCipher(clientWriteKey)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encrypted, plaintext)
	expectedBlockCiphered := []byte{
		0xc6, 0x44, 0x4a,
		0x31, 0x56, 0xef, 0x96, 0xa7, 0xc6, 0x6d, 0x92,
		0x1e, 0x3e, 0x7f, 0x22, 0x78, 0x3c, 0x81, 0x36,
		0x1f, 0xbf, 0x78, 0x34, 0x23, 0x46, 0xa8, 0x72,
		0xde, 0x6b, 0x9d, 0x89, 0x19, 0x33, 0xe2, 0x80,
		0xc2, 0xba, 0x9c, 0xc7, 0xbe, 0x26, 0xaf, 0x32,
		0x84, 0xf2, 0x3c, 0xc8, 0x86,
	}
	if diff := cmp.Diff(expectedBlockCiphered, encrypted); diff != "" {
		t.Error(diff)
	}
}
