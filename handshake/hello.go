package handshake

import (
	"github.com/arailly/mytls12/record"
	"github.com/arailly/mytls12/util"
)

const (
	TLS_RSA_WITH_AES_128_CBC_SHA          uint16 = 47
	TLS_RSA_WITH_AES_128_GCM_SHA256       uint16 = 156
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 uint16 = 0xc02f
	TLS_EMPTY_RENEGOTIATION_INFO_SCSV     uint16 = 255

	ExtTypeSNI                        ExtensionType = 0
	ExtTypeStatusRequest              ExtensionType = 5
	ExtTypeSupportedGroups            ExtensionType = 10
	ExtTypeECPointFormats             ExtensionType = 11
	ExtTypeSignatureAlgorithms        ExtensionType = 13
	ExtTypeRenegotiationInfo          ExtensionType = 65281
	ExtTypeSignedCertificateTimestamp ExtensionType = 18
	ExtTypeSupportedVersions          ExtensionType = 43
)

var (
	ExtSNI = newExtension(
		ExtTypeSNI,
		[]byte{
			0x00, 0x0c, 0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63,
			0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
		},
	)
	ExtStatusRequest = newExtension(
		ExtTypeStatusRequest,
		[]byte{0x01, 0x00, 0x00, 0x00, 0x00},
	)
	ExtSupportedGroups = newExtension(
		ExtTypeSupportedGroups,
		[]byte{
			0x00, 0x08,
			0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,
		},
	)
	ExtECPointFormats = newExtension(
		ExtTypeECPointFormats,
		[]byte{0x01, 0x00},
	)
	ExtSignatureAlgorithms = newExtension(
		ExtTypeSignatureAlgorithms,
		[]byte{
			0x00, 0x18,
			0x08, 0x04, 0x04, 0x03, 0x08, 0x07, 0x08, 0x05,
			0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01,
			0x05, 0x03, 0x06, 0x03, 0x02, 0x01, 0x02, 0x03,
		},
	)
	ExtRenegotiationInfo = newExtension(
		ExtTypeRenegotiationInfo,
		[]byte{0x00},
	)
	ExtSignedCertificateTimestamp = newExtension(
		ExtTypeSignedCertificateTimestamp,
		make([]byte, 0),
	)
	ExtSupportedVersions = newExtension(
		ExtTypeSupportedVersions,
		[]byte{0x02, 0x03, 0x03},
	)
	BasicExtensions = []Extension{
		ExtSNI,
		ExtStatusRequest,
		ExtSupportedGroups,
		ExtECPointFormats,
		ExtSignatureAlgorithms,
		ExtRenegotiationInfo,
		ExtSignedCertificateTimestamp,
		ExtSupportedVersions,
	}
)

type SessionID struct {
	length uint8
	body   []byte
}

func newSessionID(sessionID []byte) *SessionID {
	return &SessionID{
		length: uint8(len(sessionID)),
		body:   sessionID,
	}
}

type CipherSuites struct {
	length uint16
	body   []uint16
}

func newCipherSuites(suites []uint16) *CipherSuites {
	return &CipherSuites{
		length: uint16(len(suites) * 2),
		body:   suites,
	}
}

type CompressionMethods struct {
	length uint8
	body   []byte
}

func newCompressionMethods() *CompressionMethods {
	return &CompressionMethods{
		length: 1,
		body:   []byte{0x00},
	}
}

type ExtensionType uint16

type Extension struct {
	extensionType ExtensionType
	length        uint16
	extensionData []byte
}

func newExtension(extensionType ExtensionType, data []byte) Extension {
	return Extension{
		extensionType: extensionType,
		length:        uint16(len(data)),
		extensionData: data,
	}
}

type Extensions struct {
	length uint16
	body   []Extension
}

func newExtensions(exts []Extension) *Extensions {
	var length uint16 = 0
	for _, ext := range exts {
		length += 2 + 2 + ext.length
	}
	return &Extensions{
		length: length,
		body:   exts,
	}
}

type ClientHello struct {
	version            *record.ProtocolVersion
	random             []byte
	SessionID          *SessionID
	cipherSuites       *CipherSuites
	compressionMethods *CompressionMethods
	extensions         *Extensions
}

func newExtSNI(serverName string) Extension {
	data := util.ToBytes(uint16(len(serverName) + 3))
	data = append(data, 0x00)
	data = append(data, util.ToBytes(uint16(len(serverName)))...)
	data = append(data, []byte(serverName)...)
	return newExtension(
		ExtTypeSNI,
		data,
	)
}

func newBasicExtensions(serverName string) *Extensions {
	extensions := []Extension{
		newExtSNI(serverName),
		ExtStatusRequest,
		ExtSupportedGroups,
		ExtECPointFormats,
		ExtSignatureAlgorithms,
		ExtRenegotiationInfo,
		ExtSignedCertificateTimestamp,
		ExtSupportedVersions,
	}
	return newExtensions(extensions)
}

func newClientHello(
	cipherSuites []uint16,
	serverName string,
) *ClientHello {
	rng := util.NewRand()
	clientRandom := make([]byte, 32)
	rng.Read(clientRandom)
	if len(cipherSuites) == 0 {
		cipherSuites = append(
			cipherSuites,
			TLS_RSA_WITH_AES_128_CBC_SHA,
		)
	}
	return &ClientHello{
		version:            &record.ProtocolVersionTLS12,
		random:             clientRandom,
		SessionID:          newSessionID(clientRandom),
		cipherSuites:       newCipherSuites(cipherSuites),
		compressionMethods: newCompressionMethods(),
		extensions:         newBasicExtensions(serverName),
	}
}

type ServerHello struct {
	serverVersion     *record.ProtocolVersion
	random            []byte
	sessionId         *SessionID
	cipherSuite       uint16
	compressionMethod uint8
	extensions        *Extensions
}

func NewServerHello(
	random []byte,
	cipherSuite uint16,
	extensions []Extension,
) *ServerHello {
	return &ServerHello{
		serverVersion:     &record.ProtocolVersionTLS12,
		random:            random,
		sessionId:         newSessionID([]byte{}),
		cipherSuite:       cipherSuite,
		compressionMethod: 0,
		extensions:        newExtensions(extensions),
	}
}

func NewServerHelloHandshake(
	random []byte,
	cipherSuite uint16,
	extensions []Extension,
) *Handshake {
	return NewHandshake(
		HandshakeTypeServerHello,
		util.ToBytes(NewServerHello(
			random,
			cipherSuite,
			extensions,
		)),
	)
}
