package handshake

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"github.com/arailly/mytls12/util"
)

type Certificate struct {
	length       util.Uint24
	certificates []InnerCertificate
}

type InnerCertificate struct {
	length      util.Uint24
	certificate []byte
}

func NewCertificate(x509Certs []*x509.Certificate) *Certificate {
	certs := make([]InnerCertificate, 0, len(x509Certs))
	length := 0
	for _, cert := range x509Certs {
		certs = append(certs, InnerCertificate{
			length:      util.NewUint24(uint32(len(cert.Raw))),
			certificate: cert.Raw,
		})
		length += 3 + len(cert.Raw)
	}
	return &Certificate{
		length:       util.NewUint24(uint32(length)),
		certificates: certs,
	}
}

func ParseCertificatesPart(certMsg []byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0)
	offset := 0
	for {
		length := util.Uint24(certMsg[offset : offset+3])
		offset += 3
		certBytes := certMsg[offset : offset+length.Int()]
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		offset += length.Int()
		if offset >= len(certMsg) {
			break
		}
	}
	return certs, nil
}

func VerifyCertificateSignature(
	cert *x509.Certificate,
	cacert *x509.Certificate,
) error {
	certHash := sha256.Sum256(cert.RawTBSCertificate)
	err := rsa.VerifyPKCS1v15(
		cacert.PublicKey.(*rsa.PublicKey),
		crypto.SHA256,
		certHash[:],
		cert.Signature,
	)
	return err
}

func VerifyCertificateChain(
	serverName string,
	certs []*x509.Certificate,
	rootCAs []*x509.Certificate,
) error {
	if serverName != "" && serverName != certs[0].Subject.CommonName {
		return errors.New(
			"head of chain must be the server certificate",
		)
	}
	for _, cert := range certs {
		var issuerCert *x509.Certificate
		// verify by root CAs
		for _, cert_ := range rootCAs {
			if cert_.Subject.CommonName == cert.Issuer.CommonName {
				issuerCert = cert_
				break
			}
		}
		if issuerCert != nil {
			// check signature
			err := VerifyCertificateSignature(cert, issuerCert)
			if err != nil {
				return err
			}
			// verified
			return nil
		}
		// find issuer in given cert chain
		for _, cert_ := range certs {
			if cert_.Subject.CommonName == cert.Issuer.CommonName {
				issuerCert = cert_
				break
			}
		}
		if issuerCert == nil {
			return errors.New("invalid chain")
		}
		// check signature
		err := VerifyCertificateSignature(cert, issuerCert)
		if err != nil {
			return err
		}
	}
	return errors.New("not verified by root CAs")
}
