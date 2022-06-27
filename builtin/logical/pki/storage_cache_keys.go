package pki

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/vault/sdk/helper/errutil"
	"go.uber.org/atomic"

	lru "github.com/hashicorp/golang-lru"
	"github.com/hashicorp/vault/sdk/logical"
)

type keyStorageCache struct {
	lock      sync.RWMutex
	invalid   *atomic.Uint32
	idSet     map[keyID]bool
	nameIDMap map[string]keyID
	entries   *lru.Cache
}

func InitKeyStorageCache() *keyStorageCache {
	var ret keyStorageCache
	ret.invalid = atomic.NewUint32(1)

	var err error
	ret.entries, err = lru.New(32)
	if err != nil {
		panic(err)
	}

	return &ret
}

func (c *keyStorageCache) Invalidate(op func() error) error {
	if op != nil {
		c.lock.Lock()
		defer c.lock.Unlock()
		c.invalid.Inc()

		return op()
	}

	// We don't need a cache lock here as the invalidation/reset logic
	// will detect the race that happened during it's reload and not overwrite.
	c.invalid.Inc()
	return nil
}

func (c *keyStorageCache) reloadOnInvalidation(ctx context.Context, s logical.Storage) error {
	// Quick check before the lock to see if we really need to grab the lock or not.
	if c.invalid.Load() == 0 {
		return nil
	}
	c.lock.Lock()
	defer c.lock.Unlock()

	// Check to make sure by the time we have the lock if another process did the work for us.
	invalidValue := c.invalid.Load()
	if invalidValue == 0 {
		return nil
	}

	c.idSet = make(map[keyID]bool)
	c.nameIDMap = make(map[string]keyID)

	// Clear the LRU; this is necessary as some entries might've been deleted.
	c.entries.Purge()

	// List all keys which exist.
	strList, err := s.List(ctx, keyPrefix)
	if err != nil {
		return err
	}

	// Reset the key and name caches, populating the LRU.
	for _, keyIdStr := range strList {
		keyId := keyID(keyIdStr)
		_, err := c.loadKeyFromStorageAndAddToCaches(ctx, s, keyId, false)
		if err != nil {
			return err
		}
	}

	// Only if the value that we started with once we acquired the lock hasn't changed do
	// we reset the invalid flag back to 0, otherwise most likely another invalidation
	// has occurred since we started and will need to be re-performed.
	c.invalid.CAS(invalidValue, 0)
	return nil
}

func (c *keyStorageCache) listKeys(ctx context.Context, s logical.Storage) ([]keyID, error) {
	var result []keyID
	err := c.wrapInReadLock(ctx, s, func() error {
		// Now we can service the request as expected.
		result = make([]keyID, 0, len(c.idSet))
		for entry := range c.idSet {
			result = append(result, entry)
		}

		return nil
	})
	return result, err
}

func (c *keyStorageCache) wrapInReadLock(ctx context.Context, s logical.Storage, f func() error) error {
	err := c.reloadOnInvalidation(ctx, s)
	if err != nil {
		return err
	}

	c.lock.RLock()
	defer c.lock.RUnlock()
	return f()
}

func (c *keyStorageCache) keyWithID(ctx context.Context, s logical.Storage, id keyID) (bool, error) {
	var keyExists bool
	err := c.wrapInReadLock(ctx, s, func() error {
		present, ok := c.idSet[id]
		keyExists = ok && present
		return nil
	})
	return keyExists, err
}

func (c *keyStorageCache) keyWithName(ctx context.Context, s logical.Storage, name string) (keyID, error) {
	var keyId keyID
	err := c.wrapInReadLock(ctx, s, func() error {
		myKeyId, ok := c.nameIDMap[name]
		if !ok || len(myKeyId) == 0 {
			keyId = KeyRefNotFound
			return fmt.Errorf("unable to find PKI key for reference: %v", name)
		}
		keyId = myKeyId
		return nil
	})
	return keyId, err
}

func (c *keyStorageCache) fetchKeyById(ctx context.Context, s logical.Storage, keyId keyID) (*keyEntry, error) {
	var entry *keyEntry
	err := c.wrapInReadLock(ctx, s, func() error {
		// Now we can service the request as expected.
		if haveId, ok := c.idSet[keyId]; !ok || !haveId {
			return fmt.Errorf("pki key id %v does not exist", keyId)
		}

		if myEntry, ok := c.entries.Get(keyId); ok && entry != nil {
			entry = myEntry.(*keyEntry)
		}

		return nil
	})
	// either we have an entry value or an error, either way we are done...
	if err != nil || entry != nil {
		return entry, err
	}

	// Otherwise, if it doesn't exist, fetch it and add it to the LRU. We
	// once again have to upgrade our read lock to a write lock.

	c.lock.Lock()
	defer c.lock.Unlock()

	return c.loadKeyFromStorageAndAddToCaches(ctx, s, keyId, true)
}

func (c *keyStorageCache) loadKeyFromStorageAndAddToCaches(ctx context.Context, s logical.Storage, keyId keyID, keyRequired bool) (*keyEntry, error) {
	rawEntry, err := s.Get(ctx, keyPrefix+keyId.String())
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to fetch pki key: %v", err)}
	}
	if rawEntry == nil {
		if keyRequired {
			return nil, errutil.UserError{Err: fmt.Sprintf("pki key id %s does not exist", keyId.String())}
		}
		return nil, nil
	}
	var entry keyEntry
	if err = rawEntry.DecodeJSON(&entry); err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode pki key with id %s: %v", keyId.String(), err)}
	}

	c.idSet[keyId] = true
	if len(entry.Name) > 0 {
		c.nameIDMap[entry.Name] = keyId
	}

	// Add this entry to the LRU.
	c.entries.Add(keyId, &entry)
	copiedEntry := entry
	return &copiedEntry, nil
}
