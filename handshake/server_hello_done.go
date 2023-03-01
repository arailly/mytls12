package handshake

import "github.com/arailly/mytls12/util"

const (
	HandshakeTypeServerHelloDone uint8 = 14
)

type ServerHelloDone struct {
	handshakeType uint8
	length        util.Uint24
}

func NewServerHelloDone() *ServerHelloDone {
	return &ServerHelloDone{
		handshakeType: HandshakeTypeServerHelloDone,
		length:        util.NewUint24(0),
	}
}
