package record

type SecurityParameters struct {
	ConnectionEnd        string // "server" or "client"
	PRFAlgorithm         string
	BulkCipherAlgorithm  string
	CipherType           string // "stream", "block", or "aead"
	EncKeyLength         uint8
	BlockLength          uint8
	FixedIVLength        uint8
	RecordIVlength       uint8
	MACAlgorithm         string // "hmac_sha1", "hmac_sha256", ...
	MACLength            uint8
	MACKeyLength         uint8
	CompressionAlgorithm uint8
	MasterSecret         []byte // 48 Byte
	ClientRandom         []byte // 32 Byte
	ServerRandom         []byte // 32 Byte
}

func defaultSecurityParameters(connectionEnd string) *SecurityParameters {
	return &SecurityParameters{
		ConnectionEnd:        connectionEnd,
		PRFAlgorithm:         "tls_prf_sha256",
		BulkCipherAlgorithm:  "aes",
		CipherType:           "block",
		EncKeyLength:         16,
		BlockLength:          16,
		FixedIVLength:        16,
		RecordIVlength:       12,
		MACAlgorithm:         "hmac_sha1",
		MACLength:            20,
		MACKeyLength:         20,
		CompressionAlgorithm: 0,
	}
}

func defaultClientSecurityParameters() *SecurityParameters {
	return defaultSecurityParameters("client")
}

func defaultServerSecurityParameters() *SecurityParameters {
	return defaultSecurityParameters("server")
}
