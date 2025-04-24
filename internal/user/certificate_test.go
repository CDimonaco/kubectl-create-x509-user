package user_test

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cdimonaco/kubectl-create-x509-user/internal/user"
	"github.com/stretchr/testify/assert"
)

const badPemCertificate = `
-----BEGIN CERTIFICATE-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCUg9LPJPquqHY0
-----END CERTIFICATE-----
`

const badPemEC = `
-----BEGIN EC PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCUg9LPJPquqHY0
-----END EC PRIVATE KEY-----
`

const badPemPkcs1 = `
-----BEGIN RSA PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDS+GzbXFtYVbJB
wIE0SaGqIipBZZYeh6R8sOMic9UoiPV4K+202kRf0ywonzqBi2BIs2CEBfURuj/t
-----END RSA PRIVATE KEY-----
`

const badPemPkcs8 = `
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCUg9LPJPquqHY0
TWvZyPxvH29ltwUEt0zaomeqT3l238VE/r+6s7EYAJgu6CX2nR6RejiXzRMy8Jwz
-----END PRIVATE KEY-----
`

const testUsername = "cdimonaco"
const testGroup = "system:napoli"
const testExpiration = 48 * time.Hour

func TestNewX509Credentials(t *testing.T) {
	type testCase struct {
		caCertContent []byte
		caKeyContent  []byte
		shouldError   bool
		errorContent  string
	}

	ecCertificate, ecPrivateKey := readCertFixture(t, "ec")
	pkcs1Cert, pksc1PrivateKey := readCertFixture(t, "pkcs1")
	pkcs8Cert, pksc8PrivateKey := readCertFixture(t, "pkcs8")
	notCaCert, notCaPrivateKey := readCertFixture(t, "not")

	for tn, tc := range map[string]testCase{
		"should return a decode error when the caCert content is not PEM": {
			caCertContent: []byte("invalid"),
			shouldError:   true,
			errorContent:  "could not decode ca certificate, is not valid in PEM format",
		},
		"should return a malformed certificate error when caCert content is PEM but could not be parsed": {
			caCertContent: []byte(badPemCertificate),
			shouldError:   true,
			errorContent:  "malformed certificate",
		},
		"should return a decode error when the caKey content is not PEM": {
			caCertContent: ecCertificate,
			caKeyContent:  []byte("invalid"),
			shouldError:   true,
			errorContent:  "could not decode ca key, is not valid in PEM format",
		},
		"should return a decode error when the certificate provided is not a ca": {
			caCertContent: notCaCert,
			caKeyContent:  notCaPrivateKey,
			shouldError:   true,
			errorContent:  "the provided certificate is not a CA certificate",
		},
		"should return a decoding key error when the caKey content is PEM but could not be parsed as EC key": {
			caCertContent: ecCertificate,
			caKeyContent:  []byte(badPemEC),
			shouldError:   true,
			errorContent:  "could not decode the EC private key",
		},
		"should return a decoding key error when the caKey content is PEM but could not be parsed as PKCS1 key": {
			caCertContent: pkcs1Cert,
			caKeyContent:  []byte(badPemPkcs1),
			shouldError:   true,
			errorContent:  "could not decode the PKCS1 private key",
		},
		"should return a decoding key error when the caKey content is PEM but could not be parsed as PKCS8 key or any other key format": {
			caCertContent: pkcs8Cert,
			caKeyContent:  []byte(badPemPkcs8),
			shouldError:   true,
			errorContent:  "it's not compatible with EC, PKSC1 or PKSC8 private key format",
		},
		"should return a valid certificate and private key in PEM format with the provided information and expiration when the ca bundle has the private key in EC format": testCase{
			caCertContent: ecCertificate,
			caKeyContent:  ecPrivateKey,
			shouldError:   false,
		},
		"should return a valid certificate and private key in PEM format with the provided information and expiration when the ca bundle has the private key in PKSC1 format": testCase{
			caCertContent: pkcs1Cert,
			caKeyContent:  pksc1PrivateKey,
			shouldError:   false,
		},
		"should return a valid certificate and private key in PEM format with the provided information and expiration when the ca bundle has the private key in PKSC8 format": testCase{
			caCertContent: pkcs8Cert,
			caKeyContent:  pksc8PrivateKey,
			shouldError:   false,
		},
	} {
		t.Run(tn, func(t *testing.T) {
			synctest.Run(func() {
				credentials, err := user.NewX509Credentials(
					testUsername,
					testGroup,
					testExpiration,
					tc.caCertContent,
					tc.caKeyContent,
				)

				if tc.shouldError {
					assert.Nil(t, credentials)
					assert.ErrorContains(t, err, tc.errorContent)
				} else {
					assert.NoError(t, err)
					now := time.Now().UTC()

					// Check generated PEM format

					certificateDER, _ := pem.Decode(credentials.CertificatePEM)
					assert.NotNil(t, certificateDER)
					assert.Equal(t, certificateDER.Type, "CERTIFICATE")

					privateKeyDER, _ := pem.Decode(credentials.PrivateKeyPEM)
					assert.NotNil(t, privateKeyDER)
					assert.Equal(t, privateKeyDER.Type, "PRIVATE KEY")

					// Compare the field set by certificate code.

					parsedCertificate, err := x509.ParseCertificate(certificateDER.Bytes)
					assert.NoError(t, err)

					// assert.Equal(t, parsedCertificate.SerialNumber, big.NewInt(now.UnixNano()))
					assert.Equal(t, parsedCertificate.Subject.CommonName, testUsername)
					assert.Equal(t, parsedCertificate.Subject.Organization[0], testGroup)
					assert.Equal(t, parsedCertificate.NotBefore, now)
					assert.Equal(t, parsedCertificate.NotAfter, now.Add(testExpiration))
					assert.True(t, parsedCertificate.BasicConstraintsValid)
					assert.Equal(t, parsedCertificate.KeyUsage, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment)
					assert.Equal(t, parsedCertificate.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

					// Check the generate private key is PKCS8 and valid

					_, err = x509.ParsePKCS8PrivateKey(privateKeyDER.Bytes)
					assert.NoError(t, err)

					// Check if the certificate is signed from the parent ca certificate

					p, _ := pem.Decode(tc.caCertContent)
					pcert, err := x509.ParseCertificate(p.Bytes)
					assert.NoError(t, err)

					err = parsedCertificate.CheckSignatureFrom(pcert)
					assert.NoError(t, err)
				}
			})
		})
	}
}

func readCertFixture(t *testing.T, keyType string) ([]byte, []byte) {
	certContent, err := os.ReadFile(path.Join("testdata", fmt.Sprintf("%s_ca_cert.pem", keyType)))
	assert.NoError(t, err)
	privateKeyContent, err := os.ReadFile(path.Join("testdata", fmt.Sprintf("%s_ca_key.pem", keyType)))
	assert.NoError(t, err)
	return certContent, privateKeyContent
}
