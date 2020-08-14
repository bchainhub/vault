package command

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/posener/complete"
    "github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/mitchellh/cli"
)

var _ cli.Command = (*TLSCaCreateCommand)(nil)
var _ cli.CommandAutocomplete = (*TLSCaCreateCommand)(nil)


type TLSCaCreateCommand struct {
	*BaseCommand
	flagAdditionalNameConstraint []string
	flagDays                     int
	flagDomain                   string
	flagCommonName               string
	flagNameConstraint           bool
	flagBits                     int
}

func (c *TLSCaCreateCommand) Synopsis() string {
	return "Builtin helper for creating a certificate authority"
}

func (c *TLSCaCreateCommand) Help() string {
	return strings.TrimSpace(`
Usage: vault tls ca create [options]

  Create a new vault CA:

  $ vault tls ca create

Command Options:

  -additional-name-constraint=<string>
      Add name constraints for the CA. Results in rejecting certificates
      for other DNS than specified. Can be used multiple times. Only used in
      combination with -name-constraint.

  -bits=<int>
      Number of bits to use when generating the CA's private key. Defaults to
      2048.

  -common-name=<string>
      Common name is the fully qualified domain name of the certificate. Defaults 
      to Vault CA.

  -days=<int>
      Provide number of days the CA is valid for from now on. Defaults to 1825 
      (5 years).

  -domain=<string>
      Domain of vault cluster. Only used in combination with -name-constraint.
      Defaults to vault.

  -name-constraint
      Add name constraints for the CA. Results in rejecting certificates for
      other DNS than specified. If turned on, localhost and -domain will be
      added to the allowed DNS. Defaults to false.
`)
}

func (c *TLSCaCreateCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP | FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")

	f.BoolVar(&BoolVar{
		Name:   "name-constraint",
		Target: &c.flagNameConstraint,
		Usage: "Add name constraints for the CA. Results in rejecting certificates " +
			"for other DNS than specified. If turned on localhost and -domain" +
			"will be added to the allowed DNS. If the UI is going to be served " +
			"over HTTPS its DNS has to be added with -additional-constraint. It " +
			"is not possible to add that after the fact! Defaults to false.",
		Default: false,
	})

	f.StringSliceVar(&StringSliceVar{
		Name:       "additional-name-constraint",
		Target:     &c.flagAdditionalNameConstraint,
		Completion: complete.PredictNothing,
		Usage: "Add name constraints for the CA. Results in rejecting certificates " +
			"for other DNS than specified. Can be used multiple times. Only used in " +
			"combination with -name-constraint.",
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
		Usage:      "Domain of vault cluster. Only used in combination with -name-constraint. Defaults to vault.",
		Default:    "vault",
	})

	f.StringVar(&StringVar{
		Name:       "common-name",
		Target:     &c.flagCommonName,
		Completion: complete.PredictNothing,
		Usage:      "Common name is the fully qualified domain name of the certificate.",
		Default:    "Vault CA",
	})

	f.IntVar(&IntVar{
		Name:       "bits",
		Target:     &c.flagBits,
		Completion: complete.PredictNothing,
		Usage:      "Number of bits to use when generating the CA's private key.  Defaults to 2048.",
		Default:    2048,
	})

	return set
}

func (c *TLSCaCreateCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *TLSCaCreateCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *TLSCaCreateCommand) Run(args []string) int {
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

	if c.flagBits < 1 {
		c.UI.Error("Flag -bits must be greater than 0")
		return 1
	}

	if c.flagDays < 1 {
		c.UI.Error("Flag -days must be greater than 0")
		return 1
	}

	if c.flagCommonName == "" {
		c.UI.Error("Common name must not be empty")
	}

	serialNumber, err := certutil.GenerateSerialNumber()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Could not generate serial number: %s", err))
		return 1
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, c.flagBits)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Could not generate private key: %s", err))
		return 1
	}

	commonName := fmt.Sprintf("%s %s", c.flagCommonName, serialNumber)

	ca := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:       []string{"US"},
			PostalCode:    []string{"94105"},
			Province:      []string{"CA"},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"101 Second Street"},
			Organization:  []string{"HashiCorp Inc."},
			CommonName:    commonName,
		},
		NotBefore:             time.Now().Add(-30 * time.Second),
		NotAfter:              time.Now().AddDate(0, 0, c.flagDays),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Could not generate CA certificate: %s", err))
		return 1
	}

	caPem := new(bytes.Buffer)
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}

	if err := pem.Encode(caPem, certBlock); err != nil {
		c.UI.Error(fmt.Sprintf("Could not PEM encode CA certificate: %s", err))
		return 1
	}

	caCertFileName := fmt.Sprintf("%s-ca.pem", c.flagDomain)
	if err := ioutil.WriteFile(caCertFileName, caPem.Bytes(), 0644); err != nil {
		c.UI.Error(fmt.Sprintf("Could not CA certificate to file: %s", err))
		return 1
	}

	caPrivKeyPem := new(bytes.Buffer)
	keyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	}

	if err := pem.Encode(caPrivKeyPem, keyBlock); err != nil {
		c.UI.Error(fmt.Sprintf("Could not PEM encode CA key: %s", err))
		return 1
	}

	caKeyFileName := fmt.Sprintf("%s-ca-key.pem", c.flagDomain)
	if err := ioutil.WriteFile(caKeyFileName, caPrivKeyPem.Bytes(), 0644); err != nil {
		c.UI.Error(fmt.Sprintf("Could not CA key to file: %s", err))
		return 1
	}

	return 0
}
