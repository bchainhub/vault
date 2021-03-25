package rfid

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type rfidConfig struct {
	test string
}

// pathConfig returns the path configuration for CRUD operations on the backend
// configuration.
func pathConfig(b *rfidAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config$",
		Fields: map[string]*framework.FieldSchema{
			"test": {
				Type:        framework.TypeString,
				Description: "Test",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathConfigWrite,
			logical.CreateOperation: b.pathConfigWrite,
			logical.ReadOperation:   b.pathConfigRead,
		},

		HelpSynopsis:    confHelpSyn,
		HelpDescription: confHelpDesc,
	}
}

// pathConfigWrite handles create and update commands to the config
func (b *rfidAuthBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if config, err := b.config(ctx, req.Storage); err != nil {
		return nil, err
	} else if config == nil {
		return nil, nil
	} else {
		// Create a map of data to be returned
		resp := &logical.Response{
			Data: map[string]interface{}{
				"test": config.Test,
			},
		}

		return resp, nil
	}
}

// pathConfigWrite handles create and update commands to the config
func (b *rfidAuthBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	testConfig := data.Get("test").(string)
	config := &rfidConfig{
		test: testConfig,
	}

	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

const confHelpSyn = `Configures the RFID authentication backend.`
const confHelpDesc = `
The RFID authentication backend takes RFID UID's and checks if they're valid.
`
