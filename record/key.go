package record

import (
	"crypto/hmac"
	"crypto/sha256"
	"math"
)

func PRF(secret, label, seed []byte, size int) []byte {
	return PHash(secret, append(label, seed...), size)
}

func PHash(secret, seed []byte, size int) []byte {
	buf := make([]byte, 0, size+32)
	right := int(math.Log2(float64(size))) + 1
	for i := 1; i <= right; i++ {
		nextSeed := append(funcA(secret, seed, i), seed...)
		buf = append(buf, HMACHash(secret, nextSeed)...)
	}
	return buf[:size]
}

func HMACHash(secret, seed []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(seed)
	return mac.Sum(nil)
}

func funcA(secret, seed []byte, i int) []byte {
	if i == 0 {
		return seed
	} else if i > 0 {
		return HMACHash(secret, funcA(secret, seed, i-1))
	} else {
		panic("invalid input")
	}
}

func CalcMasterSecret(
	preMasterSecret []byte,
	clientRandom []byte,
	serverRandom []byte,
) []byte {
	return PRF(
		preMasterSecret,
		[]byte("master secret"),
		append(clientRandom, serverRandom...),
		48,
	)
}

func CalcKeyBlock(
	masterSecret []byte,
	serverRandom []byte,
	clientRandom []byte,
	size int,
) []byte {
	return PRF(
		masterSecret,
		[]byte("key expansion"),
		append(serverRandom, clientRandom...),
		size,
	)
}

func NewKeyBlock(
	masterSecret []byte,
	serverRandom []byte,
	clientRandom []byte,
	macKeyLength uint8,
	encKeyLength uint8,
	ivLength uint8,
) *KeyBlock {
	size := int(macKeyLength)*2 + int(encKeyLength)*2 + int(ivLength)*2
	keyBlock := PRF(
		masterSecret,
		[]byte("key expansion"),
		append(serverRandom, clientRandom...),
		size,
	)
	var offset uint8 = 0
	clientWriteMACKey := keyBlock[offset : offset+macKeyLength]
	offset += macKeyLength
	serverWriteMACKey := keyBlock[offset : offset+macKeyLength]
	offset += macKeyLength
	clientWriteKey := keyBlock[offset : offset+encKeyLength]
	offset += encKeyLength
	serverWriteKey := keyBlock[offset : offset+encKeyLength]
	offset += encKeyLength
	clientWriteIV := keyBlock[offset : offset+ivLength]
	offset += ivLength
	serverWriteIV := keyBlock[offset : offset+ivLength]
	return &KeyBlock{
		ClientWriteMACKey: clientWriteMACKey,
		ServerWriteMACKey: serverWriteMACKey,
		ClientWriteKey:    clientWriteKey,
		ServerWriteKey:    serverWriteKey,
		ClientWriteIV:     clientWriteIV,
		ServerWriteIV:     serverWriteIV,
	}
}

type KeyBlock struct {
	ClientWriteMACKey []byte
	ServerWriteMACKey []byte
	ClientWriteKey    []byte
	ServerWriteKey    []byte
	ClientWriteIV     []byte
	ServerWriteIV     []byte
}
