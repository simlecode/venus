package wallet

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/filecoin-project/go-address"
	ds "github.com/ipfs/go-datastore"
	dsq "github.com/ipfs/go-datastore/query"
	gocache "github.com/patrickmn/go-cache"
	"github.com/pborman/uuid"
	"github.com/pkg/errors"

	"github.com/filecoin-project/venus/pkg/config"
	"github.com/filecoin-project/venus/pkg/crypto"
	"github.com/filecoin-project/venus/pkg/repo"
)

const (
	cacheExpiration      = time.Hour * 5
	cacheCleanupInterval = time.Hour * 3
)

// DSBackendType is the reflect type of the DSBackend.
var DSBackendType = reflect.TypeOf(&DSBackend{})

type cache struct {
	addressCache map[address.Address]struct{}
	keyInfoCache *gocache.Cache
}

// DSBackend is a wallet backend implementation for storing addresses in a datastore.
type DSBackend struct {
	lk sync.RWMutex

	// TODO: use a better interface that supports time locks, encryption, etc.
	ds repo.Datastore

	cache *cache

	PassphraseConf config.PassphraseConfig
}

var _ Backend = (*DSBackend)(nil)

// NewDSBackend constructs a new backend using the passed in datastore.
func NewDSBackend(ds repo.Datastore, passphraseCfg config.PassphraseConfig) (*DSBackend, error) {
	result, err := ds.Query(dsq.Query{
		KeysOnly: true,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to query datastore")
	}

	list, err := result.Rest()
	if err != nil {
		return nil, errors.Wrap(err, "failed to read query results")
	}

	addrCache := make(map[address.Address]struct{}, len(list))
	for _, el := range list {
		parsedAddr, err := address.NewFromString(strings.Trim(el.Key, "/"))
		if err != nil {
			return nil, errors.Wrapf(err, "trying to restore invalid address: %s", el.Key)
		}
		addrCache[parsedAddr] = struct{}{}
	}

	kiCache := gocache.New(cacheExpiration, cacheCleanupInterval)

	return &DSBackend{
		ds: ds,
		cache: &cache{
			addressCache: addrCache,
			keyInfoCache: kiCache,
		},
		PassphraseConf: passphraseCfg,
	}, nil
}

// ImportKey loads the address in `ai` and KeyInfo `ki` into the backend
func (backend *DSBackend) ImportKey(ki *crypto.KeyInfo, password string) error {
	return backend.putKeyInfoPassphrase(ki, password)
}

// Addresses returns a list of all addresses that are stored in this backend.
func (backend *DSBackend) Addresses() []address.Address {
	backend.lk.RLock()
	defer backend.lk.RUnlock()

	var cpy []address.Address
	for addr := range backend.cache.addressCache {
		cpy = append(cpy, addr)
	}
	return cpy
}

// HasAddress checks if the passed in address is stored in this backend.
// Safe for concurrent access.
func (backend *DSBackend) HasAddress(addr address.Address) bool {
	backend.lk.RLock()
	defer backend.lk.RUnlock()

	_, ok := backend.cache.addressCache[addr]
	return ok
}

// NewAddress creates a new address and stores it.
// Safe for concurrent access.
func (backend *DSBackend) NewAddress(protocol address.Protocol, password string) (address.Address, error) {
	switch protocol {
	case address.BLS:
		return backend.newBLSAddress(password)
	case address.SECP256K1:
		return backend.newSecpAddress(password)
	default:
		return address.Undef, errors.Errorf("Unknown address protocol %d", protocol)
	}
}

func (backend *DSBackend) newSecpAddress(password string) (address.Address, error) {
	ki, err := crypto.NewSecpKeyFromSeed(rand.Reader)
	if err != nil {
		return address.Undef, err
	}

	if err := backend.putKeyInfoPassphrase(&ki, password); err != nil {
		return address.Undef, err
	}
	return ki.Address()
}

func (backend *DSBackend) newBLSAddress(password string) (address.Address, error) {
	ki, err := crypto.NewBLSKeyFromSeed(rand.Reader)
	if err != nil {
		return address.Undef, err
	}

	if err := backend.putKeyInfoPassphrase(&ki, password); err != nil {
		return address.Undef, err
	}
	return ki.Address()
}

func (backend *DSBackend) putKeyInfo(ki *crypto.KeyInfo) error {
	addr, err := ki.Address()
	if err != nil {
		return err
	}

	backend.lk.Lock()
	defer backend.lk.Unlock()

	buf := new(bytes.Buffer)
	err = ki.MarshalCBOR(buf)
	if err != nil {
		return err
	}

	if err := backend.ds.Put(ds.NewKey(addr.String()), buf.Bytes()); err != nil {
		return errors.Wrap(err, "failed to store new address")
	}

	backend.cache.addressCache[addr] = struct{}{}
	return nil
}

// SignBytes cryptographically signs `data` using the private key `priv`.
func (backend *DSBackend) SignBytes(data []byte, addr address.Address) (*crypto.Signature, error) {
	ki, err := backend.GetKeyInfo(addr)
	if err != nil {
		return nil, err
	}
	return crypto.Sign(data, ki.PrivateKey, ki.SigType)
}

// GetKeyInfo will return the private & public keys associated with address `addr`
// iff backend contains the addr.
func (backend *DSBackend) GetKeyInfo(addr address.Address) (*crypto.KeyInfo, error) {
	if !backend.HasAddress(addr) {
		return nil, errors.New("backend does not contain address")
	}

	// kib is a cbor of crypto.KeyInfo
	kib, err := backend.ds.Get(ds.NewKey(addr.String()))
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch private key from backend")
	}

	ki := &crypto.KeyInfo{}
	if err := ki.UnmarshalCBOR(bytes.NewReader(kib)); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal keyinfo from backend")
	}

	return ki, nil
}

func (backend *DSBackend) GetKeyInfoPassphrase(addr address.Address, password string) (*crypto.KeyInfo, error) {
	if !backend.HasAddress(addr) {
		return nil, errors.New("backend does not contain address")
	}

	if cache, ok := backend.cache.keyInfoCache.Get(addr.String()); ok {
		if ki, ok := cache.(*crypto.KeyInfo); ok {
			return ki, nil
		}
		backend.cache.keyInfoCache.Delete(addr.String())
	}

	key, err := backend.getKey(addr, password)
	if err != nil {
		return nil, err
	}

	backend.cache.keyInfoCache.Set(addr.String(), key.KeyInfo, cacheExpiration)

	return key.KeyInfo, nil
}

func (backend *DSBackend) getKey(addr address.Address, password string) (*Key, error) {
	b, err := backend.ds.Get(ds.NewKey(addr.String()))
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch private key from backend")
	}

	return decryptKey(b, password)
}

func (backend *DSBackend) putKeyInfoPassphrase(ki *crypto.KeyInfo, password string) error {
	addr, err := ki.Address()
	if err != nil {
		return err
	}

	backend.lk.Lock()
	defer backend.lk.Unlock()

	key := &Key{
		ID:      uuid.NewRandom(),
		Address: addr,
		KeyInfo: ki,
	}

	keyJSON, err := encryptKey(key, password, backend.PassphraseConf.ScryptN, backend.PassphraseConf.ScryptP)
	if err != nil {
		return err
	}

	if err := backend.ds.Put(ds.NewKey(key.Address.String()), keyJSON); err != nil {
		return errors.Wrapf(err, "failed to store new address: %s", key.Address.String())
	}

	backend.cache.addressCache[addr] = struct{}{}
	backend.cache.keyInfoCache.Set(addr.String(), ki, cacheExpiration)
	return nil
}

// SignBytesPassphrase cryptographically signs `data` using the private key `priv`.
func (backend *DSBackend) SignBytesPassphrase(data []byte, addr address.Address, password string) (*crypto.Signature, error) {
	ki, err := backend.GetKeyInfoPassphrase(addr, password)
	if err != nil {
		return nil, err
	}
	return crypto.Sign(data, ki.PrivateKey, ki.SigType)
}
