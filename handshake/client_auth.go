package handshake

const (
	ClientCertTypeRSA                  uint8  = 1
	ClientCertHashAlgoRSA_PKCS1_SHA256 uint16 = 0x0401
)

type CertificateRequest struct {
	CertificateTypesCount uint8
	CertificateTypes      []uint8
	SignatureHashAlgoLen  uint16
	SignatureHashAlgos    []uint16
	DistinguishedNamesLen uint16
}

func NewCertificateRequest() *CertificateRequest {
	return &CertificateRequest{
		CertificateTypesCount: 1,
		CertificateTypes:      []uint8{ClientCertTypeRSA},
		SignatureHashAlgoLen:  2,
		SignatureHashAlgos: []uint16{
			ClientCertHashAlgoRSA_PKCS1_SHA256,
		},
	}
}

type CertificateVerify struct {
	SignatureAlgo   uint16
	SignatureLength uint16
	Signature       []byte
}

func NewCertificateVerify(signature []byte) *CertificateVerify {
	return &CertificateVerify{
		SignatureAlgo:   ClientCertHashAlgoRSA_PKCS1_SHA256,
		SignatureLength: uint16(len(signature)),
		Signature:       signature,
	}
}
