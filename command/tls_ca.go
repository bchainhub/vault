package command

import (
	"strings"

	"github.com/mitchellh/cli"
)

var _ cli.Command = (*TLSCaCommand)(nil)

type TLSCaCommand struct {
	*BaseCommand
}

func (c *TLSCaCommand) Synopsis() string {
	return "Builtin helper for creating a certificate authority"
}

func (c *TLSCaCommand) Help() string {
	return strings.TrimSpace(`
Usage: vault tls ca <subcommand> [options] filename-prefix

  This command has subcommands for interacting with certificate authorities.

  Here are some simple examples, and more detailed examples are available
  in the subcommands or the documentation.

  Create a CA

    $ vault tls ca create

  For more examples, ask for subcommand help or view the documentation.

Subcommands:
    create    Create a new vault CA
`)
}

func (c *TLSCaCommand) Run(args []string) int {
	return cli.RunResultHelp
}
