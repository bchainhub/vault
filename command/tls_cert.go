package command

import (
	"strings"

	"github.com/mitchellh/cli"
)

var _ cli.Command = (*TLSCertCommand)(nil)

type TLSCertCommand struct {
	*BaseCommand
}

func (c *TLSCertCommand) Synopsis() string {
	return "Builtin helpers for creating certificates"
}

func (c *TLSCertCommand) Help() string {
	return strings.TrimSpace(`
Usage: vault tls cert <subcommand> [options] [filename-prefix]

  This command has subcommands for interacting with certificates

  Here are some simple examples, and more detailed examples are available
  in the subcommands or the documentation.

  Create a certificate

    $ vault tls cert create -server

  Create a certificate with your own CA:
	
    $ vault tls cert create -server -ca-file my-ca.pem -ca-key-file my-ca-key.pem

  For more examples, ask for subcommand help or view the documentation.

Subcommands:
    create    Create a new certificate
`)
}

func (c *TLSCertCommand) Run(args []string) int {
	return cli.RunResultHelp
}
