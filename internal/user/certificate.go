package user

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

type X509Credentials struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

const DefaultX509CredentialsExpiration time.Duration = 365 * 24 * time.Hour
const DefaultX509CredentialsGroup = "external:kubectl-create-x509-user"

func NewX509Credentials(
	username string,
	group string,
	expiration time.Duration,
	caCertPEM []byte,
	caKeyPEM []byte,
) (*X509Credentials, error) {
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, errors.New("could not decode ca certificate, is not valid in PEM format")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, err
	}

	if !caCert.BasicConstraintsValid || !caCert.IsCA {
		return nil, errors.New("the provided certificate is not a CA certificate")
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, errors.New("could not decode ca key, is not valid in PEM format")
	}
	caKey, err := decodePrivateKeyPEM(caKeyBlock)
	if err != nil {
		return nil, err
	}

	userPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	userPrivateKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(userPrivateKey)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	userCertTemplate := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   username,
			Organization: []string{group},
		},
		NotBefore:             now,
		NotAfter:              now.Add(expiration),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	userCertificateDER, err := x509.CreateCertificate(rand.Reader, &userCertTemplate, caCert, &userPrivateKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	userCertificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: userCertificateDER})
	userPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: userPrivateKeyPKCS8})

	return &X509Credentials{
		CertificatePEM: userCertificatePEM,
		PrivateKeyPEM:  userPrivateKeyPEM,
	}, nil
}

func decodePrivateKeyPEM(pemBlock *pem.Block) (any, error) {
	if strings.Contains(pemBlock.Type, "EC") {
		key, err := x509.ParseECPrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("could not decode the EC private key: %w", err)
		}
		return key, nil
	}

	if strings.Contains(pemBlock.Type, "RSA PRIVATE KEY") {
		key, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("could not decode the PKCS1 private key: %w", err)
		}
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not decode private key: %w, it's not compatible with EC, PKSC1 or PKSC8 private key format", err)
	}
	return key, nil
}
