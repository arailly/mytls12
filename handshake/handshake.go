package handshake

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"github.com/arailly/mytls12/change_cipher_spec"
	"github.com/arailly/mytls12/record"
	"github.com/arailly/mytls12/util"
)

const (
	HandshakeTypeClientHello        uint8 = 1
	HandshakeTypeServerHello        uint8 = 2
	HandshakeTypeCertificate        uint8 = 11
	HandshakeTypeServerKeyExchange  uint8 = 12
	HandshakeTypeClientKeyExchange  uint8 = 16
	HandshakeTypeFinished           uint8 = 20
	HandshakeTypeCertificateStatus  uint8 = 22
	HandshakeTypeCertificateRequest uint8 = 13
	HandshakeTypeCertificateVerify  uint8 = 15
)

type Handshake struct {
	msgType uint8
	length  util.Uint24
	body    []byte
}

func NewHandshake(
	msgType uint8,
	body []byte,
) *Handshake {
	length := util.NewUint24(uint32(len(body)))
	return &Handshake{
		msgType: msgType,
		length:  length,
		body:    body,
	}
}

func readHandshakeMessage(conn *record.Conn) ([]byte, []byte) {
	header := make([]byte, 4)
	conn.Read(header)
	length := util.Uint24(header[1:])
	body := make([]byte, length.Int())
	conn.Read(body)
	return header, body
}

func DoHandshake(conn *record.Conn, config *util.Config) {
	// Client Hello
	rng := util.NewRand()
	clientHello := newClientHello(config.CipherSuites, config.ServerName)
	chHandshake := util.ToBytes(NewHandshake(
		HandshakeTypeClientHello,
		util.ToBytes(clientHello),
	))
	conn.SendBuffer(
		record.ContentTypeHandshake,
		record.ProtocolVersionTLS10,
		chHandshake,
	)
	conn.Flush()
	conn.Params.ClientRandom = clientHello.random
	handshakeMsgs := chHandshake

	// Server Hello
	serverHelloHeader, serverHelloBody := readHandshakeMessage(conn)
	offset := 2
	serverRandom := serverHelloBody[offset : offset+32]
	offset += 32
	sessionIDLen := int(serverHelloBody[offset])
	offset += 1
	if sessionIDLen > 0 {
		sessionID := serverHelloBody[offset : offset+sessionIDLen]
		_ = sessionID
		offset += sessionIDLen
	}
	cipherSuite := uint16(serverHelloBody[offset])*256 + uint16(serverHelloBody[offset+1])

	conn.Params.ServerRandom = serverRandom
	SetCipherSuite(conn.Params, cipherSuite)

	handshakeMsgs = append(handshakeMsgs, serverHelloHeader...)
	handshakeMsgs = append(handshakeMsgs, serverHelloBody...)

	// Certificate
	certHeader, certBodyWithLen := readHandshakeMessage(conn)
	certBody := certBodyWithLen[3:]
	certs, err := ParseCertificatesPart(certBody)
	if err != nil {
		panic(err)
	}
	if err = VerifyCertificateChain(
		config.ServerName,
		certs,
		config.RootCAs,
	); err != nil {
		panic(err)
	}

	handshakeMsgs = append(handshakeMsgs, certHeader...)
	handshakeMsgs = append(handshakeMsgs, certBodyWithLen...)

	// Server Key Exchange
	var ecdhServerPubKey *ecdh.PublicKey
	if cipherSuite == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
		serverKeyExHeader, serverKeyExBody := readHandshakeMessage(conn)
		offset := 3
		ecdhServerPubKeyLen := int(serverKeyExBody[offset])
		offset += 1
		ecdhServerPubKey, err = ecdh.X25519().NewPublicKey(
			serverKeyExBody[offset : offset+ecdhServerPubKeyLen],
		)
		if err != nil {
			panic(err)
		}

		// verify signature
		serverECDHParams := serverKeyExBody[:offset+ecdhServerPubKeyLen]
		data := append(clientHello.random, serverRandom...)
		data = append(data, serverECDHParams...)
		digest := sha256.Sum256(data)

		offset += ecdhServerPubKeyLen + 2
		signatureLen := int(serverKeyExBody[offset])
		offset += 1
		signatureLen = signatureLen*256 + int(serverKeyExBody[offset])
		offset += 1
		signature := serverKeyExBody[offset : offset+signatureLen]
		_ = signature

		if err := rsa.VerifyPSS(
			certs[0].PublicKey.(*rsa.PublicKey),
			crypto.SHA256,
			digest[:],
			signature,
			nil,
		); err != nil {
			panic(err)
		}

		handshakeMsgs = append(handshakeMsgs, serverKeyExHeader...)
		handshakeMsgs = append(handshakeMsgs, serverKeyExBody...)
	}

	// Certificate Status
	handshakeType := make([]byte, 1)
	conn.Read(handshakeType)
	isCertificateStatus := (handshakeType[0] ==
		HandshakeTypeCertificateStatus)
	conn.ReadCancel(handshakeType)
	if isCertificateStatus {
		header, body := readHandshakeMessage(conn)
		handshakeMsgs = append(handshakeMsgs, header...)
		handshakeMsgs = append(handshakeMsgs, body...)
	}

	// Certificate Request
	conn.Read(handshakeType)
	clientCertRequired := (handshakeType[0] ==
		HandshakeTypeCertificateRequest)
	conn.ReadCancel(handshakeType)
	if clientCertRequired {
		header, body := readHandshakeMessage(conn)

		handshakeMsgs = append(handshakeMsgs, header...)
		handshakeMsgs = append(handshakeMsgs, body...)
	}

	// Server Hello Done
	doneHeader, doneBody := readHandshakeMessage(conn)

	handshakeMsgs = append(handshakeMsgs, doneHeader...)
	handshakeMsgs = append(handshakeMsgs, doneBody...)

	// Client Certificate
	if clientCertRequired {
		clientCertMsg := util.ToBytes(NewHandshake(
			HandshakeTypeCertificate,
			util.ToBytes(NewCertificate(
				config.Certificate.Certificate,
			)),
		))
		conn.SendBuffer(
			record.ContentTypeHandshake,
			record.ProtocolVersionTLS12,
			clientCertMsg,
		)
		handshakeMsgs = append(handshakeMsgs, clientCertMsg...)
	}

	// Client Key Exchange
	var ckeMsg []byte
	if cipherSuite == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
		curve := ecdh.X25519()
		ecdhPrivKey, err := curve.GenerateKey(rng)
		if err != nil {
			panic(err)
		}
		ecdhPubKey := ecdhPrivKey.PublicKey().Bytes()
		preMasterSecret, err := ecdhPrivKey.ECDH(ecdhServerPubKey)
		if err != nil {
			panic(err)
		}
		masterSecret := record.CalcMasterSecret(
			preMasterSecret,
			clientHello.random,
			serverRandom,
		)
		conn.SetMasterSecret(masterSecret)
		ckeMsg = util.ToBytes(NewHandshake(
			HandshakeTypeClientKeyExchange,
			util.ToBytes(NewECDHClientParams(ecdhPubKey)),
		))
	} else {
		pubKey := certs[0].PublicKey.(*rsa.PublicKey)
		pmsRandom := make([]byte, preMasterSecretRandomLength)
		rng.Read(pmsRandom)
		encryptedPMS := CalcEncryptedPreMasterSecret(
			pmsRandom,
			pubKey,
		)
		ckeMsg = util.ToBytes(NewHandshake(
			HandshakeTypeClientKeyExchange,
			util.ToBytes(encryptedPMS),
		))
		pms := util.ToBytes(NewPreMasterSecret(pmsRandom))
		masterSecret := record.CalcMasterSecret(
			pms,
			clientHello.random,
			serverRandom,
		)
		conn.SetMasterSecret(masterSecret)
	}
	conn.SendBuffer(
		record.ContentTypeHandshake,
		record.ProtocolVersionTLS12,
		util.ToBytes(ckeMsg),
	)
	handshakeMsgs = append(handshakeMsgs, ckeMsg...)

	// Certificate Verify
	if clientCertRequired {
		privKey, err := util.LoadPrivateKey("../config/client-key.der")
		if err != nil {
			panic(err)
		}
		hashedHandshakeMsg := sha256.Sum256(handshakeMsgs)
		signature, err := rsa.SignPKCS1v15(
			util.NewRand(),
			privKey,
			crypto.SHA256,
			hashedHandshakeMsg[:],
		)
		if err != nil {
			panic(err)
		}
		certificateVerifyMsg := util.ToBytes(NewHandshake(
			HandshakeTypeCertificateVerify,
			util.ToBytes(NewCertificateVerify(signature)),
		))
		conn.SendBuffer(
			record.ContentTypeHandshake,
			record.ProtocolVersionTLS12,
			certificateVerifyMsg,
		)
		handshakeMsgs = append(handshakeMsgs, certificateVerifyMsg...)
	}

	// Change Cipher Spec
	conn.SendBuffer(
		record.ContentTypeChangeCipherSpec,
		record.ProtocolVersionTLS12,
		util.ToBytes(change_cipher_spec.NewChangeCipherSpec()),
	)
	conn.StartCipherWrite()

	// Finished
	verifyData := CalcClientVerifyData(
		conn.Params.MasterSecret,
		handshakeMsgs,
	)
	finishedHandshake := util.ToBytes(NewHandshake(
		HandshakeTypeFinished,
		util.ToBytes(verifyData),
	))
	conn.SendBuffer(
		record.ContentTypeHandshake,
		record.ProtocolVersionTLS12,
		finishedHandshake,
	)
	conn.Flush()
	conn.IncrementWriteSeqNum()

	// Change Cipher Spec
	changeCipherSpec := make([]byte, 1)
	conn.Read(changeCipherSpec)
	conn.StartCipherRead()

	// Finished
	conn.SetContentTypeForAEAD(record.ContentTypeHandshake)
	_, _ = readHandshakeMessage(conn)
	conn.IncrementReadSeqNum()

	conn.SetContentTypeForAEAD(record.ContentTypeApplicationData)
}

func RespondHandshake(conn *record.Conn, config *util.Config) {
	// Client Hello
	clientHelloHeader, clientHelloBody := readHandshakeMessage(conn)
	offset := 2
	clientRandom := clientHelloBody[offset : offset+32]
	conn.Params.ClientRandom = clientRandom
	offset += 32
	sessionIDLen := int(clientHelloBody[offset])
	offset += 1 + sessionIDLen
	cipherSuiteLen, err := util.ToUint16(clientHelloBody[offset : offset+2])
	if err != nil {
		panic(err)
	}
	offset += 2
	cipherSuitesBytes := clientHelloBody[offset : offset+int(cipherSuiteLen)]
	cipherSuites := make([]uint16, 0, cipherSuiteLen/2)
	for i := 0; i < int(cipherSuiteLen); i += 2 {
		cipherSuite, err := util.ToUint16(cipherSuitesBytes[i : i+2])
		if err != nil {
			panic(err)
		}
		cipherSuites = append(cipherSuites, cipherSuite)
	}
	handshakeMsgs := clientHelloHeader
	handshakeMsgs = append(handshakeMsgs, clientHelloBody...)

	decided := false
	var cipherSuite uint16
	for _, cipherSuite = range cipherSuites {
		err := SetCipherSuite(conn.Params, cipherSuite)
		if err == nil {
			decided = true
			break
		}
	}
	if !decided {
		panic("no matched cipher suite")
	}

	// Server Hello
	rng := util.NewRand()
	serverRandom := make([]byte, 32)
	rng.Read(serverRandom)
	serverHello := util.ToBytes(NewServerHelloHandshake(
		serverRandom,
		cipherSuite,
		[]Extension{
			ExtRenegotiationInfo,
			ExtECPointFormats,
		},
	))
	conn.SendBuffer(
		record.ContentTypeHandshake,
		record.ProtocolVersionTLS12,
		serverHello,
	)
	conn.Params.ServerRandom = serverRandom
	handshakeMsgs = append(handshakeMsgs, serverHello...)

	// Certificate
	certificateMsg := util.ToBytes(NewHandshake(
		HandshakeTypeCertificate,
		util.ToBytes(NewCertificate(
			config.Certificate.Certificate,
		)),
	))
	conn.SendBuffer(
		record.ContentTypeHandshake,
		record.ProtocolVersionTLS12,
		certificateMsg,
	)
	handshakeMsgs = append(handshakeMsgs, certificateMsg...)

	// Server Key Exchange
	var ecdhPrivKey *ecdh.PrivateKey
	if cipherSuite == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
		curve := ecdh.X25519()
		ecdhPrivKey, err = curve.GenerateKey(rng)
		if err != nil {
			panic(err)
		}
		ecdhPubKey := ecdhPrivKey.PublicKey().Bytes()
		ecdhServerParams := util.ToBytes(NewECDHServerParams(ecdhPubKey))
		data := append(clientRandom, serverRandom...)
		data = append(data, ecdhServerParams...)
		digest := sha256.Sum256(data)
		sig, err := rsa.SignPSS(
			rng,
			config.Certificate.PrivateKey.(*rsa.PrivateKey),
			crypto.SHA256,
			digest[:],
			&rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
			},
		)
		if err != nil {
			panic(err)
		}
		serverKeyExMsg := util.ToBytes(NewHandshake(
			HandshakeTypeServerKeyExchange,
			util.ToBytes(NewECDHServerParamsWithSign(
				ecdhPubKey,
				sig,
			)),
		))
		conn.SendBuffer(
			record.ContentTypeHandshake,
			record.ProtocolVersionTLS12,
			serverKeyExMsg,
		)
		handshakeMsgs = append(handshakeMsgs, serverKeyExMsg...)
	}

	// Certificate Request
	if config.ClientAuth == util.RequestClientCert {
		certReqMsg := util.ToBytes(NewHandshake(
			HandshakeTypeCertificateRequest,
			util.ToBytes(NewCertificateRequest()),
		))
		conn.SendBuffer(
			record.ContentTypeHandshake,
			record.ProtocolVersionTLS12,
			certReqMsg,
		)
		handshakeMsgs = append(handshakeMsgs, certReqMsg...)
	}

	// Server Hello Done
	serverHelloDoneMsg := util.ToBytes(NewServerHelloDone())
	conn.SendBuffer(
		record.ContentTypeHandshake,
		record.ProtocolVersionTLS12,
		serverHelloDoneMsg,
	)
	conn.Flush()
	handshakeMsgs = append(handshakeMsgs, serverHelloDoneMsg...)

	// Client Certificate
	var clientCert *x509.Certificate
	if config.ClientAuth == util.RequestClientCert {
		clientCertHeader, clientCertBody := readHandshakeMessage(conn)
		clientCerts, err := ParseCertificatesPart(clientCertBody[3:])
		if err != nil {
			panic(err)
		}
		clientCert = clientCerts[0]
		err = VerifyCertificateChain(
			"",
			clientCerts,
			config.RootCAs,
		)
		if err != nil {
			panic(err)
		}
		handshakeMsgs = append(handshakeMsgs, clientCertHeader...)
		handshakeMsgs = append(handshakeMsgs, clientCertBody...)
	}

	// Client Key Exchange
	clientKeyExHeader, clientKeyExBody := readHandshakeMessage(conn)
	var preMasterSecret []byte
	if cipherSuite == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
		clientPubKeyLen := clientKeyExBody[0]
		clientPubKey, err := ecdh.X25519().NewPublicKey(
			clientKeyExBody[1 : 1+clientPubKeyLen],
		)
		if err != nil {
			panic(err)
		}
		preMasterSecret, err = ecdhPrivKey.ECDH(clientPubKey)
		if err != nil {
			panic(err)
		}
	} else {
		encryptedPMSLen, err := util.ToUint16(clientKeyExBody[0:2])
		if err != nil {
			panic(err)
		}
		encryptedPMS := clientKeyExBody[2 : 2+encryptedPMSLen]

		privKey := config.Certificate.PrivateKey
		preMasterSecret, err = rsa.DecryptPKCS1v15(
			util.NewRand(),
			privKey.(*rsa.PrivateKey),
			encryptedPMS,
		)
		if err != nil {
			panic(err)
		}
	}
	masterSecret := record.CalcMasterSecret(
		preMasterSecret,
		clientRandom,
		serverRandom,
	)
	conn.SetMasterSecret(masterSecret)
	handshakeMsgs = append(handshakeMsgs, clientKeyExHeader...)
	handshakeMsgs = append(handshakeMsgs, clientKeyExBody...)

	// Certificate Verify
	if config.ClientAuth == util.RequestClientCert {
		certVerifyHeader, certVerifyBody := readHandshakeMessage(conn)
		// signatureAlgo := certVerifyBody[:2]
		signatureLen := uint16(certVerifyBody[2])*256 +
			uint16(certVerifyBody[3])
		signature := certVerifyBody[4 : 4+signatureLen]
		hashedHandshakeMsg := sha256.Sum256(handshakeMsgs)
		err := rsa.VerifyPKCS1v15(
			clientCert.PublicKey.(*rsa.PublicKey),
			crypto.SHA256,
			hashedHandshakeMsg[:],
			signature,
		)
		if err != nil {
			panic(err)
		}

		handshakeMsgs = append(handshakeMsgs, certVerifyHeader...)
		handshakeMsgs = append(handshakeMsgs, certVerifyBody...)
	}

	// Change Cipher Spec
	changeCipherSpec := make([]byte, 1)
	conn.Read(changeCipherSpec)
	conn.StartCipherRead()

	// Finished
	conn.SetContentTypeForAEAD(record.ContentTypeHandshake)
	finishedHeader, finishedBody := readHandshakeMessage(conn)
	handshakeMsgs = append(handshakeMsgs, finishedHeader...)
	handshakeMsgs = append(handshakeMsgs, finishedBody...)
	conn.IncrementReadSeqNum()

	// Change Cipher Spec
	conn.SendBuffer(
		record.ContentTypeChangeCipherSpec,
		record.ProtocolVersionTLS12,
		util.ToBytes(change_cipher_spec.NewChangeCipherSpec()),
	)
	conn.StartCipherWrite()

	// Finished
	verifyData := CalcServerVerifyData(masterSecret, handshakeMsgs)
	finishedHandshake := util.ToBytes(NewHandshake(
		HandshakeTypeFinished,
		util.ToBytes(verifyData),
	))
	conn.SendBuffer(
		record.ContentTypeHandshake,
		record.ProtocolVersionTLS12,
		finishedHandshake,
	)
	conn.Flush()
	conn.IncrementWriteSeqNum()
	conn.SetContentTypeForAEAD(record.ContentTypeApplicationData)
}

func SetCipherSuite(
	params *record.SecurityParameters,
	cipherSuite uint16,
) error {
	switch cipherSuite {
	case TLS_RSA_WITH_AES_128_CBC_SHA:
		params.PRFAlgorithm = "tls_prf_sha256"
		params.BulkCipherAlgorithm = "aes"
		params.CipherType = "block"
		params.EncKeyLength = 16
		params.BlockLength = 16
		params.FixedIVLength = 16
		params.RecordIVlength = 16
		params.MACAlgorithm = "hmac_sha1"
		params.MACLength = 20
		params.MACKeyLength = 20
	case TLS_RSA_WITH_AES_128_GCM_SHA256:
		params.PRFAlgorithm = "tls_prf_sha256"
		params.BulkCipherAlgorithm = "aes"
		params.CipherType = "aead"
		params.EncKeyLength = 16
		params.MACKeyLength = 0
		params.RecordIVlength = 8
		params.FixedIVLength = 4
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		params.PRFAlgorithm = "tls_prf_sha256"
		params.BulkCipherAlgorithm = "aes"
		params.CipherType = "aead"
		params.EncKeyLength = 16
		params.MACKeyLength = 0
		params.RecordIVlength = 8
		params.FixedIVLength = 4
	default:
		return errors.New("unsupported cipher suite")
	}
	return nil
}
