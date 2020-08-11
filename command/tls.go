package command

import (
	"strings"

	"github.com/mitchellh/cli"
)

var _ cli.Command = (*TLSCommand)(nil)

type TLSCommand struct {
	*BaseCommand
}

func (c *TLSCommand) Synopsis() string {
	return "Builtin helpers for creating CAs and certificates"
}

func (c *TLSCommand) Help() string {
	return strings.TrimSpace(`
Usage: vault tls <subcommand> <subcommand> [options]

  This command has subcommands for interacting with Vault TLS.

  Here are some simple examples, and more detailed examples are available
  in the subcommands or the documentation.

  Create a CA

    $ vault tls ca create

  Create a server certificate

    $ vault tls cert create -server

  Create a client certificate

    $ vault tls cert create -client

  For more examples, ask for subcommand help or view the documentation.
`)
}

func (c *TLSCommand) Run(args []string) int {
	return cli.RunResultHelp
}
