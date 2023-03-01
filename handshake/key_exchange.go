package handshake

import (
	"crypto/rsa"

	"github.com/arailly/mytls12/record"
	"github.com/arailly/mytls12/util"
)

const (
	preMasterSecretRandomLength        = 46
	CurveTypeNamedCurve         uint8  = 3
	NamedCurveX25519            uint16 = 0x001d
	SignatureAlgoRSA            uint16 = 0x0804
)

type PreMasterSecret struct {
	clientVersion record.ProtocolVersion
	random        []byte // 46 Bytes
}

func NewPreMasterSecret(random []byte) *PreMasterSecret {
	return &PreMasterSecret{
		clientVersion: record.ProtocolVersionTLS12,
		random:        random,
	}
}

type EncryptedPreMasterSecret struct {
	length       uint16
	encryptedKey []byte
}

func CalcEncryptedPreMasterSecret(
	random []byte,
	pubKey *rsa.PublicKey,
) *EncryptedPreMasterSecret {
	rng := util.NewRand()
	preMasterSecret := util.ToBytes(NewPreMasterSecret(random))
	encrypted, err := rsa.EncryptPKCS1v15(rng, pubKey, preMasterSecret)
	if err != nil {
		panic(err)
	}
	return &EncryptedPreMasterSecret{
		length:       uint16(len(encrypted)),
		encryptedKey: encrypted,
	}
}

type ECDHClientParams struct {
	PubKeyLength uint8
	PubKey       []byte
}

func NewECDHClientParams(pubKey []byte) *ECDHClientParams {
	return &ECDHClientParams{
		PubKeyLength: uint8(len(pubKey)),
		PubKey:       pubKey,
	}
}

type ECDHServerParams struct {
	CurveType    uint8
	NamedCurve   uint16
	PubKeyLength uint8
	PubKey       []byte
}

func NewECDHServerParams(pubKey []byte) *ECDHServerParams {
	return &ECDHServerParams{
		CurveType:    CurveTypeNamedCurve,
		NamedCurve:   NamedCurveX25519,
		PubKeyLength: uint8(len(pubKey)),
		PubKey:       pubKey,
	}
}

type ECDHServerParamsWithSign struct {
	CurveType       uint8
	NamedCurve      uint16
	PubKeyLength    uint8
	PubKey          []byte
	SignatureAlgo   uint16
	SignatureLength uint16
	Signature       []byte
}

func NewECDHServerParamsWithSign(pubKey, signature []byte) *ECDHServerParamsWithSign {
	return &ECDHServerParamsWithSign{
		CurveType:       CurveTypeNamedCurve,
		NamedCurve:      NamedCurveX25519,
		PubKeyLength:    uint8(len(pubKey)),
		PubKey:          pubKey,
		SignatureAlgo:   SignatureAlgoRSA,
		SignatureLength: uint16(len(signature)),
		Signature:       signature,
	}
}
