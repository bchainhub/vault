package command

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"github.com/posener/complete"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/mitchellh/cli"
)

var _ cli.Command = (*TLSCertCreateCommand)(nil)

type TLSCertCreateCommand struct {
	*BaseCommand
	flagAdditionalDNS 			 []string
	flagAdditionalIP             []string
	flagDays                     int
	flagDomain                   string
	flagClient                   bool
	flagServer                   bool
	flagCA                       string
	flagKey                      string
	flagBits                     int
	flagCommonName               string
}

func (c *TLSCertCreateCommand) Synopsis() string {
	return "Builtin helper for creating certificates"
}

func (c *TLSCertCreateCommand) Help() string {
	return strings.TrimSpace(`
Usage: vault tls cert create [options]

  Create a new server certificate:

  $ vault tls cert create -server

  Create a new client certificate:

  $ vault tls cert create -client
`)
}

func (c *TLSCertCreateCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP | FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")

	f.BoolVar(&BoolVar{
		Name:   "server",
		Target: &c.flagServer,
		Usage: "Generate server certificate.",
		Default: false,
	})

	f.BoolVar(&BoolVar{
		Name:   "client",
		Target: &c.flagClient,
		Usage: "Generate client certificate.",
		Default: false,
	})

	f.StringVar(&StringVar{
		Name:       "ca",
		Target:     &c.flagCA,
		Completion: complete.PredictNothing,
		Usage:      "Provide path to the ca. Defaults to #DOMAIN#-ca.pem",
		Default:    "#DOMAIN#-ca.pem",
	})

	f.StringVar(&StringVar{
		Name:       "key",
		Target:     &c.flagKey,
		Completion: complete.PredictNothing,
		Usage:      "Provide path to the key. Defaults to #DOMAIN#-ca-key.pem",
		Default:    "#DOMAIN#-ca-key.pem",
	})

	f.IntVar(&IntVar{
		Name:       "days",
		Target:     &c.flagDays,
		Completion: complete.PredictNothing,
		Usage:      "Provide number of days the CA is valid for from now on. Defaults to 5 years.",
		Default:    1825,
	})

	f.StringVar(&StringVar{
		Name:       "domain",
		Target:     &c.flagDomain,
		Completion: complete.PredictNothing,
		Usage:      "Domain of vault cluster. Defaults to vault.",
		Default:    "vault",
	})

	f.StringVar(&StringVar{
		Name:       "common-name",
		Target:     &c.flagCommonName,
		Completion: complete.PredictNothing,
		Usage:      "Common name is the fully qualified domain name of the certificate.",
		Default:    "Vault",
	})

	f.StringSliceVar(&StringSliceVar{
		Name:       "additional-dnsname",
		Target:     &c.flagAdditionalDNS,
		Completion: complete.PredictNothing,
		Usage: "Provide an additional dnsname for Subject Alternative Names. " +
			"localhost is always included. This flag may be provided multiple times.",
	})

	f.StringSliceVar(&StringSliceVar{
		Name:       "additional-ipaddress",
		Target:     &c.flagAdditionalIP,
		Completion: complete.PredictNothing,
		Usage: "Provide an additional ipaddress for Subject Alternative Names. " +
			"127.0.0.1 is always included. This flag may be provided multiple times.",
	})

	f.IntVar(&IntVar{
		Name:       "bits",
		Target:     &c.flagBits,
		Completion: complete.PredictNothing,
		Usage:      "Number of bits to use when generating the servers private key.  Defaults to 2048.",
		Default:    2048,
	})

	return set
}

func (c *TLSCertCreateCommand) Run(args []string) int {
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	args = f.Args()
	if len(args) > 0 {
		c.UI.Error(fmt.Sprintf("Too many arguments (expected 0, got %d)", len(args)))
		return 1
	}

	if c.flagCA == "" {
		c.UI.Error("Please provide the certificate authority certificate")
		return 1
	}

	if c.flagKey == "" {
		c.UI.Error("Please provide the certificate authority key")
		return 1
	}

	if !c.flagServer && !c.flagClient || c.flagServer && c.flagClient {
		c.UI.Error("Please provide either -server, -client")
	}

	if c.flagDays < 1 {
		c.UI.Error("Flag -days must be greater than 0")
		return 1
	}

	if c.flagBits < 1 {
		c.UI.Error("Flag -bits must be greater than 0")
		return 1
	}

	if c.flagCommonName == "" {
		c.UI.Error("Flag -common-name must not be empty")
		return 1
	}

	var DNSNames []string
	for _, d := range c.flagAdditionalDNS {
		if len(d) > 0 {
			DNSNames = append(DNSNames, strings.TrimSpace(d))
		}
	}
	var IPAddresses []net.IP
	for _, i := range c.flagAdditionalIP {
		if len(i) > 0 {
			IPAddresses = append(IPAddresses, net.ParseIP(strings.TrimSpace(i)))
		}
	}

	var extKeyUsage []x509.ExtKeyUsage
	var prefix string
	if c.flagServer {
		DNSNames = append(DNSNames, "localhost")
		IPAddresses = append(IPAddresses, net.ParseIP("127.0.0.1"))
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		prefix = fmt.Sprintf("%s-server", c.flagDomain)
	} else if c.flagClient {
		DNSNames = append(DNSNames, []string{"localhost"}...)
		IPAddresses = append(IPAddresses, net.ParseIP("127.0.0.1"))
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		prefix = fmt.Sprintf("%s-client", c.flagDomain)
	} else {
		c.UI.Error("Neither client or server configured - should not happen")
		return 1
	}

	caFile := strings.Replace(c.flagCA, "#DOMAIN#", c.flagDomain, 1)
	keyFile := strings.Replace(c.flagKey, "#DOMAIN#", c.flagDomain, 1)
	cert, err := ioutil.ReadFile(caFile)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error reading CA: %s", err))
		return 1
	}
	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error reading CA key: %s", err))
		return 1
	}

	signer, err := parseSigner(string(key))
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	parent, err := parseCert(string(cert))
	if err != nil {
		c.UI.Error(fmt.Sprintf("Could not parse CA certificate: %s", err))
		return 1
	}

	keys, err := rsa.GenerateKey(rand.Reader, c.flagBits)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Could not generate private key: %s", err))
		return 1
	}

	id, err := keyID(keys.Public())
	if err != nil {
		c.UI.Error(fmt.Sprintf("Could not retrieve key ID from signing key: %s", err))
		return 1
	}

	serialNumber, err := certutil.GenerateSerialNumber()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Could not generate serial number: %s", err))
		return 1
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject: 			   pkix.Name{CommonName:    c.flagCommonName},
		NotBefore:             time.Now().Add(-30 * time.Second),
		NotAfter:              time.Now().AddDate(0, 0, c.flagDays),
		IsCA:                  false,
		ExtKeyUsage:           extKeyUsage,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		SubjectKeyId:          id,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, keys.Public(), signer)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Could not generate certificate: %s", err))
		return 1
	}

	certPem := new(bytes.Buffer)
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}

	if err := pem.Encode(certPem, certBlock); err != nil {
		c.UI.Error(fmt.Sprintf("Could not PEM encode certificate: %s", err))
		return 1
	}

	certFileName := fmt.Sprintf("%s.pem", prefix)
	if err := ioutil.WriteFile(certFileName, certPem.Bytes(), 0644); err != nil {
		c.UI.Error(fmt.Sprintf("Could not write certificate to file: %s", err))
		return 1
	}

	certPrivKeyPem := new(bytes.Buffer)
	keyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keys),
	}

	if err := pem.Encode(certPrivKeyPem, keyBlock); err != nil {
		c.UI.Error(fmt.Sprintf("Could not PEM encode key: %s", err))
		return 1
	}

	certKeyFileName := fmt.Sprintf("%s-key.pem", prefix)
	if err := ioutil.WriteFile(certKeyFileName, certPrivKeyPem.Bytes(), 0644); err != nil {
		c.UI.Error(fmt.Sprintf("Could not write key to file: %s", err))
		return 1
	}

	return 0
}

func parseSigner(pemValue string) (crypto.Signer, error) {
	// The _ result below is not an error but the remaining PEM bytes.
	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, fmt.Errorf("no PEM-encoded data found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unknown PEM block type for signing key: %s", block.Type)
	}
}

func parseCert(pemValue string) (*x509.Certificate, error) {
	// The _ result below is not an error but the remaining PEM bytes.
	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, fmt.Errorf("no PEM-encoded data found")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("first PEM-block should be CERTIFICATE type")
	}

	return x509.ParseCertificate(block.Bytes)
}

// KeyId returns a x509 KeyId from the given signing key.
func keyID(raw interface{}) ([]byte, error) {
	switch raw.(type) {
	case *rsa.PublicKey:
	default:
		return nil, fmt.Errorf("invalid key type: %T", raw)
	}

	// This is not standard; RFC allows any unique identifier as long as they
	// match in subject/authority chains but suggests specific hashing of DER
	// bytes of public key including DER tags.
	bs, err := x509.MarshalPKIXPublicKey(raw)
	if err != nil {
		return nil, err
	}

	// String formatted
	kID := sha256.Sum256(bs)
	return kID[:], nil
}