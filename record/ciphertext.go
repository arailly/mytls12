package record

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"

	"github.com/arailly/mytls12/util"
)

type TLSCipherText struct {
	contentType uint8
	version     ProtocolVersion
	length      uint16
	fragment    []byte
}

type GenericBlockCipher struct {
	iv            []byte
	blockCiphered []byte
}

func CalcGenericBlockCipher(
	contentType uint8,
	version ProtocolVersion,
	macKey []byte,
	encKey []byte,
	content []byte,
	seqNum uint64,
	iv []byte,
) *GenericBlockCipher {
	mac := calcMAC(
		macKey,
		seqNum,
		contentType,
		version,
		content,
	)
	blockCiphered := CalcBlockCiphered(
		content,
		mac,
		encKey,
		iv,
	)
	return &GenericBlockCipher{
		iv:            iv,
		blockCiphered: blockCiphered,
	}
}

func calcMAC(
	macKey []byte,
	seqNum uint64,
	contentType uint8,
	version ProtocolVersion,
	content []byte,
) []byte {
	mac := hmac.New(sha1.New, macKey)
	macSeed := util.ToBytes(seqNum)
	macSeed = append(macSeed, contentType)
	macSeed = append(macSeed, util.ToBytes(version)...)
	contentLength := uint16(len(content))
	macSeed = append(macSeed, util.ToBytes(contentLength)...)
	macSeed = append(macSeed, content...)
	mac.Write(macSeed)
	return mac.Sum(nil)
}

// type BlockCiphered struct {
// 	content       []byte
// 	mac           []byte
// 	padding       []byte
// 	paddingLength uint8
// }

func CalcBlockCiphered(
	content []byte,
	mac []byte,
	writeKey []byte,
	iv []byte,
) []byte {
	plainText := append(content, mac...)
	padding := 16 - (len(content)+len(mac)+1)%16
	for i := 0; i <= padding; i++ {
		plainText = append(plainText, uint8(padding))
	}
	block, err := aes.NewCipher(writeKey)
	if err != nil {
		panic(err)
	}
	cipherText := make([]byte, len(plainText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, plainText)
	return cipherText
}

func NewTLSCipherText(
	contentType uint8,
	version ProtocolVersion,
	fragment []byte,
) *TLSCipherText {
	return &TLSCipherText{
		contentType: contentType,
		version:     version,
		length:      uint16(len(fragment)),
		fragment:    fragment,
	}
}

func DecryptCBC(
	fragment []byte,
	key []byte,
	ivLength uint8,
) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	iv := fragment[:ivLength]
	blockCiphered := fragment[ivLength:]
	buf := make([]byte, len(blockCiphered))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(buf, blockCiphered)
	padding := int(buf[len(buf)-1])
	return buf[:len(buf)-20-padding-1]
}

type GenericAEADCipher struct {
	explicitNonce       []byte
	aeadCipheredContent []byte
}

func CalcGenericAEADCipher(
	content []byte,
	key []byte,
	implicitNonce []byte,
	explicitNonce []byte,
	additionalData []byte,
) *GenericAEADCipher {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce := append(implicitNonce, explicitNonce...)
	cipherText := gcm.Seal(nil, nonce, content, additionalData)
	return &GenericAEADCipher{
		explicitNonce:       explicitNonce,
		aeadCipheredContent: cipherText,
	}
}

func DecryptAEAD(
	cipherText []byte,
	key []byte,
	nonce []byte,
	additionalData []byte,
) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	plainText, err := gcm.Open(nil, nonce, cipherText, additionalData)
	if err != nil {
		panic(err)
	}
	return plainText
}
