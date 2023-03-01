package record

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/arailly/mytls12/util"
)

func Dial(addr string) (*Conn, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Conn{
		netConn: conn,
		Params:  defaultClientSecurityParameters(),
	}, nil
}

func Listen(addr string) (*Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Listener{l}, nil
}

type Listener struct {
	netListener net.Listener
}

func (l *Listener) Accept() (*Conn, error) {
	conn, err := l.netListener.Accept()
	if err != nil {
		return nil, err
	}
	return &Conn{
		netConn: conn,
		Params:  defaultServerSecurityParameters(),
	}, nil
}

func (l *Listener) Addr() string {
	return l.netListener.Addr().String()
}

func (l *Listener) Close() error {
	return l.netListener.Close()
}

type Conn struct {
	netConn            net.Conn
	Params             *SecurityParameters
	keyBlock           *KeyBlock
	writeSeqNum        uint64
	readSeqNum         uint64
	writeKey           []byte
	readKey            []byte
	writeMACKey        []byte
	readMACKey         []byte
	writeImplicitNonce []byte
	readImplicitNonce  []byte
	CipherRead         bool
	CipherWrite        bool
	contentTypeForAEAD uint8

	mutex   sync.Mutex
	sendBuf []byte
	recvBuf []byte
}

func (c *Conn) Close() {
	c.netConn.Close()
}

func (c *Conn) StartCipherRead() {
	c.CipherRead = true
}

func (c *Conn) StartCipherWrite() {
	c.CipherWrite = true
}

func (c *Conn) IncrementWriteSeqNum() {
	c.writeSeqNum++
}

func (c *Conn) IncrementReadSeqNum() {
	c.readSeqNum++
}

func (c *Conn) SetContentTypeForAEAD(contentType uint8) {
	c.contentTypeForAEAD = contentType
}

func (c *Conn) Flush() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	_, err := c.netConn.Write(c.sendBuf)
	if err != nil {
		panic(err)
	}
	c.sendBuf = make([]byte, 0)
}

func (c *Conn) SendBuffer(
	contentType uint8,
	version ProtocolVersion,
	data []byte,
) {
	if c.CipherWrite {
		c.bufferCipherText(contentType, version, data)
	} else {
		c.bufferPlainText(contentType, version, data)
	}
}

func (c *Conn) bufferPlainText(
	contentType uint8,
	version ProtocolVersion,
	data []byte,
) {
	record := NewTLSPlainText(contentType, version, data)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.sendBuf = append(c.sendBuf, util.ToBytes(record)...)
}

func (c *Conn) Read(b []byte) (int, error) {
	if len(b) <= len(c.recvBuf) {
		length := copy(b, c.recvBuf)
		c.recvBuf = c.recvBuf[length:]
		return length, nil
	}
	header := make([]byte, 5)
	n, err := c.netConn.Read(header)
	if n == 0 && err == io.EOF {
		length := copy(b, c.recvBuf)
		c.recvBuf = make([]byte, 0)
		return length, nil
	}
	if n != 5 {
		panic("read record error")
	}
	length := int(header[3])*256 + int(header[4])
	for {
		fragment := make([]byte, 0)
		for i := 0; i < length; i++ {
			f := make([]byte, 1)
			_, err := c.netConn.Read(f)
			if err != nil {
				return 0, err
			}
			fragment = append(fragment, f...)
		}

		if c.CipherRead {
			if c.Params.CipherType == "block" {
				decrypted := DecryptCBC(fragment, c.readKey, c.Params.FixedIVLength)
				c.recvBuf = append(c.recvBuf, decrypted...)
			} else if c.Params.CipherType == "aead" {
				explicitNonce := fragment[:8]
				nonce := append(c.readImplicitNonce, explicitNonce...)
				cipherText := fragment[8:]
				additionalData := append(
					util.ToBytes(c.readSeqNum),
					c.contentTypeForAEAD,
				)
				additionalData = append(
					additionalData,
					util.ToBytes(ProtocolVersionTLS12)...,
				)
				length := util.ToBytes(uint16(len(cipherText) - 16))
				additionalData = append(additionalData, length...)
				decrypted := DecryptAEAD(
					cipherText,
					c.readKey,
					nonce,
					additionalData,
				)
				c.recvBuf = append(c.recvBuf, decrypted...)
			}
		} else {
			c.recvBuf = append(c.recvBuf, fragment...)
		}
		if len(c.recvBuf) >= len(b) {
			break
		}
		time.Sleep(time.Microsecond)
	}
	length = copy(b, c.recvBuf)
	c.recvBuf = c.recvBuf[length:]
	return length, nil
}

func (c *Conn) ReadCancel(b []byte) {
	c.recvBuf = append(b, c.recvBuf...)
}

func (c *Conn) bufferCipherText(
	contentType uint8,
	version ProtocolVersion,
	data []byte,
) {
	rng := util.NewRand()

	var fragment []byte
	if c.Params.CipherType == "block" {
		iv := make([]byte, 16)
		rng.Read(iv)
		genericBlockCipher := CalcGenericBlockCipher(
			contentType,
			version,
			c.writeMACKey,
			c.writeKey,
			data,
			c.writeSeqNum,
			iv,
		)
		fragment = util.ToBytes(genericBlockCipher)
	} else if c.Params.CipherType == "aead" {
		explicitNonce := util.ToBytes(c.writeSeqNum)
		additionalData := append(explicitNonce, contentType)
		additionalData = append(additionalData, util.ToBytes(version)...)
		length := util.ToBytes(uint16(len(data)))
		additionalData = append(additionalData, length...)
		genericAEADCipher := CalcGenericAEADCipher(
			data,
			c.writeKey,
			c.writeImplicitNonce,
			explicitNonce,
			additionalData,
		)
		fragment = util.ToBytes(genericAEADCipher)
	}
	record := NewTLSCipherText(contentType, version, fragment)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.sendBuf = append(c.sendBuf, util.ToBytes(record)...)
}

func (c *Conn) SetMasterSecret(masterSecret []byte) {
	c.Params.MasterSecret = masterSecret
	keyBlock := NewKeyBlock(
		c.Params.MasterSecret,
		c.Params.ServerRandom,
		c.Params.ClientRandom,
		c.Params.MACKeyLength,
		c.Params.EncKeyLength,
		c.Params.FixedIVLength,
	)
	c.keyBlock = keyBlock
	if c.Params.ConnectionEnd == "client" {
		c.writeKey = keyBlock.ClientWriteKey
		c.readKey = keyBlock.ServerWriteKey
		c.writeMACKey = keyBlock.ClientWriteMACKey
		c.readMACKey = keyBlock.ServerWriteMACKey
		c.writeImplicitNonce = append([]byte{}, keyBlock.ClientWriteIV...)
		c.readImplicitNonce = append([]byte{}, keyBlock.ServerWriteIV...)
	} else {
		c.writeKey = keyBlock.ServerWriteKey
		c.readKey = keyBlock.ClientWriteKey
		c.writeMACKey = keyBlock.ServerWriteMACKey
		c.readMACKey = keyBlock.ClientWriteMACKey
		c.writeImplicitNonce = append([]byte{}, keyBlock.ServerWriteIV...)
		c.readImplicitNonce = append([]byte{}, keyBlock.ClientWriteIV...)
	}
}
