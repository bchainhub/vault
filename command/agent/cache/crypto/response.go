package crypto

import (
	"context"
	"crypto/rand"
	"fmt"
	mathRand "math/rand"
	"time"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/vault/api"
)

var _ KeyManager = (*ResponseEncryptionKey)(nil)

// ResponseEncryptionKey ...
type ResponseEncryptionKey struct {
	renewable bool
	wrapper   *aead.Wrapper
	token     []byte
	client    *api.Client
	Notify    chan struct{}
}

// NewResponseWrappedKey ..
func NewResponseWrappedKey(existingToken []byte, client *api.Client) (*ResponseEncryptionKey, error) {
	r := &ResponseEncryptionKey{
		renewable: true,
		wrapper:   aead.NewWrapper(nil),
		client:    client,
	}

	r.client.AddHeader("X-Vault-Wrap-TTL", "60")
	r.wrapper.SetConfig(map[string]string{"key_id": KeyID})

	var rootKey []byte = nil
	if len(existingToken) != 0 {
		r.token = existingToken
		secret, err := r.unwrap()
		if err != nil {
			return r, err
		}
		fmt.Println(fmt.Sprintf("%+v", secret.Data))

		key := secret.Data["key"].(string)
		rootKey = []byte(key)
	}

	if rootKey == nil {
		newKey := make([]byte, 32)
		_, err := rand.Read(newKey)
		if err != nil {
			return r, err
		}
		rootKey = newKey
	}

	if err := r.wrapper.SetAESGCMKeyBytes(rootKey); err != nil {
		return r, err
	}

	return r, nil
}

// GetKey ...
func (r *ResponseEncryptionKey) GetKey() []byte {
	return r.wrapper.GetKeyBytes()
}

// GetPersistentKey ...
func (r *ResponseEncryptionKey) GetPersistentKey() ([]byte, error) {
	if r.token == nil {
		r.WrapForStorage()
	}
	return r.wrapper.GetKeyBytes(), nil
}

// Renewable ...
func (r *ResponseEncryptionKey) Renewable() bool {
	return r.renewable
}

// Renewer ...
func (r *ResponseEncryptionKey) Renewer(ctx context.Context) error {
	for {
		secret, err := r.rewrap()
		if err != nil {
			return err
		}
		r.token = []byte(secret.WrapInfo.Token)

		// Notify listener token has changed
		<-r.Notify

		sleep := float64(time.Duration(secret.WrapInfo.TTL)*time.Second) / 3.0
		sleep = sleep * (mathRand.Float64() + 1) / 2.0

		select {
		case <-time.After(time.Duration(sleep) * time.Second):
		case <-ctx.Done():
			return nil
		}
	}
}

// Encrypt ...
func (r *ResponseEncryptionKey) Encrypt(ctx context.Context, plaintext, aad []byte) ([]byte, error) {
	blob, err := r.wrapper.Encrypt(ctx, plaintext, aad)
	if err != nil {
		return nil, err
	}
	return blob.Ciphertext, nil
}

// Decrypt ...
func (r *ResponseEncryptionKey) Decrypt(ctx context.Context, ciphertext, aad []byte) ([]byte, error) {
	blob := &wrapping.EncryptedBlobInfo{
		Ciphertext: ciphertext,
		KeyInfo: &wrapping.KeyInfo{
			KeyID: KeyID,
		},
	}
	return r.wrapper.Decrypt(ctx, blob, aad)
}

func (r *ResponseEncryptionKey) WrapForStorage() error {
	secret, err := r.wrap()
	if err != nil {
		return err
	}
	r.token = []byte(secret.WrapInfo.Token)
	return nil
}

func (r *ResponseEncryptionKey) wrap() (*api.Secret, error) {
	data := map[string]interface{}{"key": string(r.wrapper.GetKeyBytes())}
	return r.client.Logical().Write("/sys/wrapping/wrap", data)
}

func (r *ResponseEncryptionKey) unwrap() (*api.Secret, error) {
	//data := map[string]interface{}{"token": string(r.token)}
	return r.client.Logical().Write("/sys/wrapping/unwrap", nil)
}

func (r *ResponseEncryptionKey) rewrap() (*api.Secret, error) {
	data := map[string]interface{}{"token": string(r.token)}
	return r.client.Logical().Write("/sys/wrapping/rewrap", data)
}
