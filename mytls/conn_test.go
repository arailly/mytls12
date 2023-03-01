package mytls_test

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/arailly/mytls12/handshake"
	"github.com/arailly/mytls12/mytls"
	"github.com/arailly/mytls12/util"
)

func TestClient(t *testing.T) {
	testCases := []struct {
		name         string
		cipherSuites []uint16
	}{
		// {
		// 	name: "TLS_RSA_WITH_AES_128_CBC_SHA",
		// 	cipherSuites: []uint16{
		// 		handshake.TLS_RSA_WITH_AES_128_CBC_SHA,
		// 	},
		// },
		// {
		// 	name: "TLS_RSA_WITH_AES_128_GCM_SHA256",
		// 	cipherSuites: []uint16{
		// 		handshake.TLS_RSA_WITH_AES_128_GCM_SHA256,
		// 	},
		// },
		{
			name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			cipherSuites: []uint16{
				handshake.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		},
	}
	cacert, err := util.LoadCertificate("../config/ca.der")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// setup
			l, err := tls.Listen(
				"tcp",
				":0",
				util.DefaultTLSServerConfig("../config"),
			)
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				conn, _ := l.Accept()
				conn.Write([]byte("hello world"))
				conn.Close()
			}()
			config := &util.Config{
				RootCAs:      []*x509.Certificate{cacert},
				CipherSuites: tc.cipherSuites,
			}
			// exercise
			conn, err := mytls.Dial(l.Addr().String(), config)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			data := make([]byte, 11)
			conn.Read(data)
			// verify
			if string(data) != "hello world" {
				t.Errorf(string(data))
			}
		})
	}
}

func TestCybozu(t *testing.T) {
	cacert, err := util.LoadCertificate(
		"../config/Starfield Services Root Certificate Authority - G2.der",
	)
	if err != nil {
		t.Fatal(err)
	}
	config := &util.Config{
		RootCAs: []*x509.Certificate{cacert},
	}
	conn, err := mytls.Dial("www.cybozu.com:443", config)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Send([]byte("GET / HTTP/1.1\r\nHOST: www.cybozu.com\r\n\r\n"))
	data := make([]byte, 8)
	conn.Read(data)
	if string(data) != "HTTP/1.1" {
		t.Errorf(string(data))
	}
}

func TestServer(t *testing.T) {
	testCases := []struct {
		name         string
		cipherSuites []uint16
	}{
		// {
		// 	name: "TLS_RSA_WITH_AES_128_CBC_SHA",
		// 	cipherSuites: []uint16{
		// 		handshake.TLS_RSA_WITH_AES_128_CBC_SHA,
		// 	},
		// },
		// {
		// 	name: "TLS_RSA_WITH_AES_128_GCM_SHA256",
		// 	cipherSuites: []uint16{
		// 		handshake.TLS_RSA_WITH_AES_128_GCM_SHA256,
		// 	},
		// },
		{
			name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			cipherSuites: []uint16{
				handshake.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		},
	}
	cert, err := util.LoadCertificate("../config/server.der")
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := util.LoadPrivateKey("../config/server-key.der")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := mytls.Listen(":0", &util.Config{
				Certificate: util.NewCertificate(
					[]*x509.Certificate{cert},
					privKey,
				),
			})
			t.Log("server:", l.Addr())
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				conn, _ := l.Accept()
				conn.Send([]byte("hello world"))
				conn.Close()
			}()
			tlsConfig := util.DefaultTLSClientConfig()
			tlsConfig.CipherSuites = tc.cipherSuites
			conn, err := tls.Dial("tcp", l.Addr(), tlsConfig)
			if err != nil {
				t.Error(err)
			}
			data := make([]byte, 11)
			conn.Read(data)
			if string(data) != "hello world" {
				t.Error(string(data))
			}
		})
	}
}

func TestClientAuth(t *testing.T) {
	serverConfig := util.DefaultTLSServerConfig("../config")
	serverConfig.ClientAuth = tls.RequestClientCert

	l, err := tls.Listen("tcp", ":0", serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, _ := l.Accept()
		conn.Write([]byte("hello world"))
		conn.Close()
	}()
	cacert, err := util.LoadCertificate("../config/ca.der")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := util.LoadCertificate("../config/client.der")
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := util.LoadPrivateKey("../config/client-key.der")
	if err != nil {
		t.Fatal(err)
	}
	clientConfig := &util.Config{
		RootCAs: []*x509.Certificate{cacert},
		Certificate: util.NewCertificate(
			[]*x509.Certificate{cert},
			privKey,
		),
	}
	conn, err := mytls.Dial(l.Addr().String(), clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	data := make([]byte, 11)
	conn.Read(data)
	if string(data) != "hello world" {
		t.Errorf(string(data))
	}
}

func TestServerClientAuth(t *testing.T) {
	cacert, err := util.LoadCertificate("../config/ca.der")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := util.LoadCertificate("../config/server.der")
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := util.LoadPrivateKey("../config/server-key.der")
	if err != nil {
		t.Fatal(err)
	}
	l, err := mytls.Listen(":0", &util.Config{
		Certificate: util.NewCertificate(
			[]*x509.Certificate{cert},
			privKey,
		),
		ClientAuth: util.RequestClientCert,
		RootCAs:    []*x509.Certificate{cacert},
	})
	t.Log("server:", l.Addr())
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, _ := l.Accept()
		conn.Send([]byte("hello world"))
		conn.Close()
	}()
	clientConfig := util.DefaultTLSClientConfig()
	clientKeyPair, err := tls.LoadX509KeyPair(
		"../config/client.pem",
		"../config/client-key.pem",
	)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig.Certificates = []tls.Certificate{clientKeyPair}
	conn, err := tls.Dial("tcp", l.Addr(), clientConfig)
	if err != nil {
		t.Error(err)
	}
	data := make([]byte, 11)
	conn.Read(data)
	if string(data) != "hello world" {
		t.Error(string(data))
	}
}
