package alert

import (
	"github.com/arailly/mytls12/record"
	"github.com/arailly/mytls12/util"
)

const (
	AlertLevelWarning uint8 = 1
	AlertLevelFatal   uint8 = 2

	AlertDescCloseNotify uint8 = 0
)

type Alert struct {
	Level       uint8
	Description uint8
}

func SendAlert(conn *record.Conn, level, desc uint8) {
	alert := Alert{
		Level:       level,
		Description: desc,
	}
	conn.SetContentTypeForAEAD(record.ContentTypeAlert)
	conn.SendBuffer(
		record.ContentTypeAlert,
		record.ProtocolVersionTLS12,
		util.ToBytes(alert),
	)
	conn.Flush()
}
