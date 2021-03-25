package rfid

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
)

type CLIHandler struct{}

func (h *CLIHandler) Auth(c *api.Client, m map[string]string) (*api.Secret, error) {
	var data struct {
		Mount string `mapstructure:"mount"`
		Role  string `mapstructure:"role"`
		UID   int    `mapstructure:"uid"`
	}
	if err := mapstructure.WeakDecode(m, &data); err != nil {
		return nil, err
	}

	if data.Mount == "" {
		data.Mount = "rfid"
	}

	if data.UID == 0 {
		return nil, fmt.Errorf("UID is required")
	}

	options := map[string]interface{}{
		"role": data.Role,
		"uid":  data.UID,
	}
	path := fmt.Sprintf("auth/%s/login", data.Mount)
	secret, err := c.Logical().Write(path, options)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("empty response from credential provider")
	}

	return secret, nil
}

func (h *CLIHandler) Help() string {
	help := `
Usage: vault login -method=rfid [CONFIG K=V...]

      $ vault login -method=rfid name=foobar

Configuration:

  name=<string>
`

	return strings.TrimSpace(help)
}
