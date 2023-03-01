package change_cipher_spec

import (
	"github.com/arailly/mytls12/record"
	"github.com/arailly/mytls12/util"
)

type ChangeCipherSpec struct {
	Type uint8
}

func NewChangeCipherSpec() *ChangeCipherSpec {
	return &ChangeCipherSpec{
		Type: 1,
	}
}

func NewChangeCipherSpecRecord() *record.TLSPlainText {
	return record.NewTLSPlainText(
		record.ContentTypeChangeCipherSpec,
		record.ProtocolVersionTLS12,
		util.ToBytes(ChangeCipherSpec{
			Type: 1,
		}),
	)
}
