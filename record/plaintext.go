package record

const (
	ContentTypeHandshake        uint8 = 22
	ContentTypeChangeCipherSpec uint8 = 20
	ContentTypeAlert            uint8 = 21
	ContentTypeApplicationData  uint8 = 23
)

var (
	ProtocolVersionTLS10 = ProtocolVersion{
		Major: 3,
		Minor: 1,
	}
	ProtocolVersionTLS12 = ProtocolVersion{
		Major: 3,
		Minor: 3,
	}
)

type ProtocolVersion struct {
	Major uint8
	Minor uint8
}

func (p *ProtocolVersion) Bytes() []byte {
	return []byte{p.Major, p.Minor}
}

type TLSPlainText struct {
	contentType uint8
	version     ProtocolVersion
	length      uint16
	fragment    []byte
}

func NewTLSPlainText(
	contentType uint8,
	version ProtocolVersion,
	fragment []byte,
) *TLSPlainText {
	return &TLSPlainText{
		contentType: contentType,
		version:     version,
		length:      uint16(len(fragment)),
		fragment:    fragment,
	}
}

func FromBytes(recordBytes []byte) []*TLSPlainText {
	records := make([]*TLSPlainText, 0)
	offset := 0
	for {
		contentType := recordBytes[offset]
		offset++
		version := ProtocolVersion{
			Major: recordBytes[offset],
			Minor: recordBytes[offset+1],
		}
		offset += 2
		length := uint16(recordBytes[offset])*256 +
			uint16(recordBytes[offset+1])
		offset += 2
		fragment := recordBytes[offset : offset+int(length)]
		records = append(records, NewTLSPlainText(
			contentType,
			version,
			fragment,
		))
		offset += int(length)
		if offset >= len(recordBytes) {
			break
		}
	}
	return records
}

func GetContentsFromBytes(recordBytes []byte) []byte {
	records := FromBytes(recordBytes)
	result := make([]byte, 0)
	for _, record := range records {
		result = append(result, record.fragment...)
	}
	return result
}
