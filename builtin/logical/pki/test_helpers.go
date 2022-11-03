package pki

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// Setup helpers
func createBackendWithStorage(t testing.TB) (*backend, logical.Storage) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	var err error
	b := Backend(config)
	err = b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	// Assume for our tests we have performed the migration already.
	b.pkiStorageVersion.Store(1)
	return b, config.StorageView
}

func mountPKIEndpoint(t testing.TB, client *api.Client, path string) {
	err := client.Sys().Mount(path, &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "32h",
		},
	})
	require.NoError(t, err, "failed mounting pki endpoint")
}

// Signing helpers
func requireSignedBy(t *testing.T, cert *x509.Certificate, signingCert *x509.Certificate) {
	if err := cert.CheckSignatureFrom(signingCert); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

// Certificate helper
func parseCert(t *testing.T, pemCert string) *x509.Certificate {
	block, _ := pem.Decode([]byte(pemCert))
	require.NotNil(t, block, "failed to decode PEM block")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func requireMatchingPublicKeys(t *testing.T, cert *x509.Certificate, key crypto.PublicKey) {
	certPubKey := cert.PublicKey
	areEqual, err := certutil.ComparePublicKeysAndType(certPubKey, key)
	require.NoError(t, err, "failed comparing public keys: %#v", err)
	require.True(t, areEqual, "public keys mismatched: got: %v, expected: %v", certPubKey, key)
}

func getSelfSigned(t *testing.T, subject, issuer *x509.Certificate, key *rsa.PrivateKey) (string, *x509.Certificate) {
	t.Helper()
	selfSigned, err := x509.CreateCertificate(rand.Reader, subject, issuer, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(selfSigned)
	if err != nil {
		t.Fatal(err)
	}
	pemSS := strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: selfSigned,
	})))
	return pemSS, cert
}

// CRL related helpers
func getCrlCertificateList(t *testing.T, client *api.Client, mountPoint string) pkix.TBSCertificateList {
	path := fmt.Sprintf("/v1/%s/crl", mountPoint)
	return getParsedCrlAtPath(t, client, path).TBSCertList
}

func parseCrlPemBytes(t *testing.T, crlPem []byte) pkix.TBSCertificateList {
	certList, err := x509.ParseCRL(crlPem)
	require.NoError(t, err)
	return certList.TBSCertList
}

func requireSerialNumberInCRL(t *testing.T, revokeList pkix.TBSCertificateList, serialNum string) bool {
	serialsInList := make([]string, 0, len(revokeList.RevokedCertificates))
	for _, revokeEntry := range revokeList.RevokedCertificates {
		formattedSerial := certutil.GetHexFormatted(revokeEntry.SerialNumber.Bytes(), ":")
		serialsInList = append(serialsInList, formattedSerial)
		if formattedSerial == serialNum {
			return true
		}
	}

	if t != nil {
		t.Fatalf("the serial number %s, was not found in the CRL list containing: %v", serialNum, serialsInList)
	}

	return false
}

func getParsedCrl(t *testing.T, client *api.Client, mountPoint string) *pkix.CertificateList {
	path := fmt.Sprintf("/v1/%s/crl", mountPoint)
	return getParsedCrlAtPath(t, client, path)
}

func getParsedCrlAtPath(t *testing.T, client *api.Client, path string) *pkix.CertificateList {
	req := client.NewRequest("GET", path)
	resp, err := client.RawRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	crlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	if len(crlBytes) == 0 {
		t.Fatalf("expected CRL in response body")
	}

	crl, err := x509.ParseDERCRL(crlBytes)
	if err != nil {
		t.Fatal(err)
	}
	return crl
}

func getParsedCrlFromBackend(t *testing.T, b *backend, s logical.Storage, path string) *pkix.CertificateList {
	resp, err := CBRead(b, s, path)
	if err != nil {
		t.Fatal(err)
	}

	crl, err := x509.ParseDERCRL(resp.Data[logical.HTTPRawBody].([]byte))
	if err != nil {
		t.Fatal(err)
	}
	return crl
}

// Direct storage backend helpers (b, s := createBackendWithStorage(t)) which
// are mostly compatible with client.Logical() operations. The main difference
// is that the JSON round-tripping hasn't occurred, so values are as the
// backend returns them (e.g., []string instead of []interface{}).
func CBReq(b *backend, s logical.Storage, operation logical.Operation, path string, data map[string]interface{}) (*logical.Response, error) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation:  operation,
		Path:       path,
		Data:       data,
		Storage:    s,
		MountPoint: "pki/",
	})
	if err != nil || resp == nil {
		return resp, err
	}

	if msg, ok := resp.Data["error"]; ok && msg != nil && len(msg.(string)) > 0 {
		return resp, fmt.Errorf("%s", msg)
	}

	return resp, nil
}

func CBRead(b *backend, s logical.Storage, path string) (*logical.Response, error) {
	return CBReq(b, s, logical.ReadOperation, path, make(map[string]interface{}))
}

func CBWrite(b *backend, s logical.Storage, path string, data map[string]interface{}) (*logical.Response, error) {
	return CBReq(b, s, logical.UpdateOperation, path, data)
}

func CBPatch(b *backend, s logical.Storage, path string, data map[string]interface{}) (*logical.Response, error) {
	return CBReq(b, s, logical.PatchOperation, path, data)
}

func CBList(b *backend, s logical.Storage, path string) (*logical.Response, error) {
	return CBReq(b, s, logical.ListOperation, path, make(map[string]interface{}))
}

func CBDelete(b *backend, s logical.Storage, path string) (*logical.Response, error) {
	return CBReq(b, s, logical.DeleteOperation, path, make(map[string]interface{}))
}

func requireFieldsSetInResp(t *testing.T, resp *logical.Response, fields ...string) {
	var missingFields []string
	for _, field := range fields {
		value, ok := resp.Data[field]
		if !ok || value == nil {
			missingFields = append(missingFields, field)
		}
	}

	require.Empty(t, missingFields, "The following fields were required but missing from response:\n%v", resp.Data)
}

func requireSuccessNonNilResponse(t *testing.T, resp *logical.Response, err error, msgAndArgs ...interface{}) {
	require.NoError(t, err, msgAndArgs...)
	if resp.IsError() {
		errContext := fmt.Sprintf("Expected successful response but got error: %v", resp.Error())
		require.Falsef(t, resp.IsError(), errContext, msgAndArgs...)
	}
	require.NotNil(t, resp, msgAndArgs...)
}

func requireSuccessNilResponse(t *testing.T, resp *logical.Response, err error, msgAndArgs ...interface{}) {
	require.NoError(t, err, msgAndArgs...)
	if resp.IsError() {
		errContext := fmt.Sprintf("Expected successful response but got error: %v", resp.Error())
		require.Falsef(t, resp.IsError(), errContext, msgAndArgs...)
	}
	if resp != nil {
		msg := fmt.Sprintf("expected nil response but got: %v", resp)
		require.Nilf(t, resp, msg, msgAndArgs...)
	}
}
