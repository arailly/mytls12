package record_test

import (
	"testing"

	"github.com/arailly/mytls12/record"
	"github.com/google/go-cmp/cmp"
)

func TestPlainRead(t *testing.T) {
	serverHello := []byte{
		// 0x16, 0x03, 0x03, 0x00, 0x37,
		0x02, 0x00, 0x00,
		0x33, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00,
		0x0b, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0b,
		0x00, 0x02, 0x01, 0x00,
	}
	listener, err := record.Listen(":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, _ := listener.Accept()
		conn.SendBuffer(
			record.ContentTypeHandshake,
			record.ProtocolVersionTLS12,
			serverHello,
		)
		conn.Flush()
	}()
	conn, err := record.Dial(listener.Addr())
	if err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, 3)
	_, err = conn.Read(actual)
	if err != nil {
		t.Error(err)
	}
	diff := cmp.Diff(serverHello[:3], actual)
	if diff != "" {
		t.Error(diff)
	}
	actual = make([]byte, len(serverHello)-3)
	_, err = conn.Read(actual)
	if err != nil {
		t.Error(err)
	}
	diff = cmp.Diff(serverHello[3:], actual)
	if diff != "" {
		t.Error(diff)
	}
}

func TestCipherReadSend(t *testing.T) {
	listener, err := record.Listen(":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, _ := listener.Accept()
		conn.Params.MasterSecret = CalcMasterSecret(t)
		conn.Params.ClientRandom = clientRandom
		conn.Params.ServerRandom = serverRandom
		conn.SetMasterSecret(conn.Params.MasterSecret)
		conn.StartCipherWrite()
		conn.SendBuffer(
			record.ContentTypeHandshake,
			record.ProtocolVersionTLS12,
			finished,
		)
		conn.Flush()
	}()
	conn, err := record.Dial(listener.Addr())
	if err != nil {
		t.Fatal(err)
	}
	conn.Params.MasterSecret = CalcMasterSecret(t)
	conn.Params.ClientRandom = clientRandom
	conn.Params.ServerRandom = serverRandom
	conn.SetMasterSecret(conn.Params.MasterSecret)
	conn.StartCipherRead()
	actual := make([]byte, 3)
	conn.Read(actual)
	diff := cmp.Diff(finished[:3], actual)
	if diff != "" {
		t.Error(diff)
	}
	actual = make([]byte, len(finished)-3)
	conn.Read(actual)
	diff = cmp.Diff(finished[3:], actual)
	if diff != "" {
		t.Error(diff)
	}
}

func TestCipherGCM(t *testing.T) {
	listener, err := record.Listen(":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, _ := listener.Accept()
		conn.Params.MasterSecret = CalcMasterSecret(t)
		conn.Params.ClientRandom = clientRandom
		conn.Params.ServerRandom = serverRandom
		conn.SetMasterSecret(conn.Params.MasterSecret)
		conn.StartCipherWrite()
		conn.SendBuffer(
			record.ContentTypeHandshake,
			record.ProtocolVersionTLS12,
			finished,
		)
		conn.Flush()
	}()
	conn, err := record.Dial(listener.Addr())
	if err != nil {
		t.Fatal(err)
	}
	conn.Params.MasterSecret = CalcMasterSecret(t)
	conn.Params.ClientRandom = clientRandom
	conn.Params.ServerRandom = serverRandom
	conn.SetMasterSecret(conn.Params.MasterSecret)
	conn.StartCipherRead()
	actual := make([]byte, 3)
	conn.Read(actual)
	diff := cmp.Diff(finished[:3], actual)
	if diff != "" {
		t.Error(diff)
	}
	actual = make([]byte, len(finished)-3)
	conn.Read(actual)
	diff = cmp.Diff(finished[3:], actual)
	if diff != "" {
		t.Error(diff)
	}
}
