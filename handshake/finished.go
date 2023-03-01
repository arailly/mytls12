package handshake

import (
	"crypto/sha256"

	"github.com/arailly/mytls12/record"
	"github.com/arailly/mytls12/util"
)

type Finished struct {
	length     util.Uint24
	verifyData []byte
}

func NewFinished(verifyData []byte) *Finished {
	return &Finished{
		length:     util.NewUint24(uint32(len(verifyData))),
		verifyData: verifyData,
	}
}

func calcVerifyData(
	masterSecret []byte,
	handshakeMessages []byte,
	label []byte,
) []byte {
	h := sha256.New()
	h.Write(handshakeMessages)
	handshakeMessagesSum := h.Sum(nil)
	return record.PRF(masterSecret, label, handshakeMessagesSum, 12)
}

func CalcClientVerifyData(masterSecret, handshakeMessages []byte) []byte {
	return calcVerifyData(
		masterSecret,
		handshakeMessages,
		[]byte("client finished"),
	)
}

func CalcServerVerifyData(masterSecret, handshakeMessages []byte) []byte {
	return calcVerifyData(
		masterSecret,
		handshakeMessages,
		[]byte("server finished"),
	)
}
