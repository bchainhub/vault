package rfid

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathLogin returns the path configurations for login endpoints
func pathLogin(b *rfidAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: `Name of the role against which the login is being attempted. This field is required`,
			},
			"uid": {
				Type:        framework.TypeString,
				Description: `This field is required.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation:         b.pathLogin,
			logical.AliasLookaheadOperation: b.pathLogin,
		},

		HelpSynopsis:    pathLoginHelpSyn,
		HelpDescription: pathLoginHelpDesc,
	}
}

// pathLogin is used to authenticate to this backend
func (b *rfidAuthBackend) pathLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)
	if len(roleName) == 0 {
		return logical.ErrorResponse("missing role"), nil
	}

	uidRaw := data.Get("uid").(string)
	if uidRaw == "" {
		return logical.ErrorResponse("missing uid"), nil
	}

	uid, err := strconv.Atoi(uidRaw)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	b.l.RLock()
	defer b.l.RUnlock()

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("invalid role name \"%s\"", roleName)), nil
	}

	if role.UID != uid {
		return nil, errors.New("login unauthorized")
	}

	auth := &logical.Auth{
		Alias: &logical.Alias{
			Name: roleName,
		},
		InternalData: map[string]interface{}{
			"role": roleName,
			"uid":  uidRaw,
		},
		Metadata: map[string]string{
			"role": roleName,
		},
	}

	role.PopulateTokenAuth(auth)

	return &logical.Response{
		Auth: auth,
	}, nil
}

// Invoked when the token issued by this backend is attempting a renewal.
func (b *rfidAuthBackend) pathLoginRenew() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		roleName := req.Auth.InternalData["role"].(string)
		if roleName == "" {
			return nil, fmt.Errorf("failed to fetch role_name during renewal")
		}

		b.l.RLock()
		defer b.l.RUnlock()

		// Ensure that the Role still exists.
		role, err := b.role(ctx, req.Storage, roleName)
		if err != nil {
			return nil, fmt.Errorf("failed to validate role %s during renewal:%s", roleName, err)
		}
		if role == nil {
			return nil, fmt.Errorf("role %s does not exist during renewal", roleName)
		}

		resp := &logical.Response{Auth: req.Auth}
		resp.Auth.TTL = role.TokenTTL
		resp.Auth.MaxTTL = role.TokenMaxTTL
		resp.Auth.Period = role.TokenPeriod
		return resp, nil
	}
}

const pathLoginHelpSyn = `Authenticates Kubernetes service accounts with Vault.`
const pathLoginHelpDesc = `
Authenticate Kubernetes service accounts.
`
