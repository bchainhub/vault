package crypto

import (
	"fmt"
	"testing"

	log "github.com/hashicorp/go-hclog"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
)

func TestCrypto_ResponseWrappingNewKey(t *testing.T) {
	var err error
	coreConfig := &vault.CoreConfig{
		DisableMlock:       true,
		DisableCache:       true,
		Logger:             log.NewNullLogger(),
		CredentialBackends: map[string]logical.Factory{},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})

	cluster.Start()
	defer cluster.Cleanup()

	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)
	client := cores[0].Client

	responseWrappedKey, err := NewResponseWrappedKey([]byte{}, client)
	if err != nil {
		t.Fatalf(fmt.Sprintf("unexpected error: %s", err))
	}

	key := responseWrappedKey.GetKey()
	if key == nil {
		t.Fatalf(fmt.Sprintf("key is nil, it shouldn't be: %s", key))
	}

	plaintextInput := []byte("test")
	aad := []byte("")

	ciphertext, err := responseWrappedKey.Encrypt(nil, plaintextInput, aad)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if ciphertext == nil {
		t.Fatalf("ciphertext nil, it shouldn't be")
	}

	plaintext, err := responseWrappedKey.Decrypt(nil, ciphertext, aad)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if string(plaintext) != string(plaintextInput) {
		t.Fatalf("expected %s, got %s", plaintextInput, plaintext)
	}
}

func TestCrypto_ResponseWrappingExistingKey(t *testing.T) {
	var err error
	coreConfig := &vault.CoreConfig{
		DisableMlock:       true,
		DisableCache:       true,
		Logger:             log.NewNullLogger(),
		CredentialBackends: map[string]logical.Factory{},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})

	cluster.Start()
	defer cluster.Cleanup()

	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)
	client := cores[0].Client

	responseWrappedKey, err := NewResponseWrappedKey([]byte{}, client)
	if err != nil {
		t.Fatalf(fmt.Sprintf("unexpected error: %s", err))
	}

	key := responseWrappedKey.GetKey()
	if key == nil {
		t.Fatalf(fmt.Sprintf("key is nil, it shouldn't be: %s", key))
	}
	fmt.Println(string(key))

	plaintextInput := []byte("test")
	aad := []byte("")

	ciphertext, err := responseWrappedKey.Encrypt(nil, plaintextInput, aad)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if ciphertext == nil {
		t.Fatalf("ciphertext nil, it shouldn't be")
	}

	responseWrappedKey, err = NewResponseWrappedKey(key, client)
	if err != nil {
		t.Fatalf(fmt.Sprintf("unexpected error: %s", err))
	}

	key = responseWrappedKey.Get()
	if key == nil {
		t.Fatalf(fmt.Sprintf("key is nil, it shouldn't be: %s", key))
	}

	plaintext, err := responseWrappedKey.Decrypt(nil, ciphertext, aad)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if string(plaintext) != string(plaintextInput) {
		t.Fatalf("expected %s, got %s", plaintextInput, plaintext)
	}
}

/*
	if !responseWrappedKey.Renewable() {
		t.Fatalf("expected renewable, was not")
	}

	notify := make(chan struct{})
	go responseWrappedKey.Renewer(nil, notify)
*/
