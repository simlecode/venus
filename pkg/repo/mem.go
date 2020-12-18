package repo

import (
	"sync"

	"github.com/ipfs/go-datastore"
	dss "github.com/ipfs/go-datastore/sync"
	keystore "github.com/ipfs/go-ipfs-keystore"

	"github.com/filecoin-project/venus/app/paths"
	"github.com/filecoin-project/venus/pkg/config"
)

// MemRepo is an in-memory implementation of the Repo interface.
type MemRepo struct {
	// lk guards the config
	lk             sync.RWMutex
	C              *config.Config
	D              Datastore
	Ks             keystore.Keystore
	W              Datastore
	Chain          Datastore
	Meta           Datastore
	version        uint
	jsonrpcAddress string
	rustfulAddress string
	token          []byte
}

var _ Repo = (*MemRepo)(nil)

// NewInMemoryRepo makes a new instance of MemRepo
func NewInMemoryRepo() *MemRepo {
	return &MemRepo{
		C:       config.NewDefaultConfig(),
		D:       dss.MutexWrap(datastore.NewMapDatastore()),
		Ks:      keystore.MutexWrap(keystore.NewMemKeystore()),
		W:       dss.MutexWrap(datastore.NewMapDatastore()),
		Chain:   dss.MutexWrap(datastore.NewMapDatastore()),
		Meta:    dss.MutexWrap(datastore.NewMapDatastore()),
		version: Version,
	}
}

// ConfigModule returns the configuration object.
func (mr *MemRepo) Config() *config.Config {
	mr.lk.RLock()
	defer mr.lk.RUnlock()

	return mr.C
}

// ReplaceConfig replaces the current config with the newly passed in one.
func (mr *MemRepo) ReplaceConfig(cfg *config.Config) error {
	mr.lk.Lock()
	defer mr.lk.Unlock()

	mr.C = cfg

	return nil
}

// Datastore returns the datastore.
func (mr *MemRepo) Datastore() datastore.Batching {
	return mr.D
}

// Keystore returns the keystore.
func (mr *MemRepo) Keystore() keystore.Keystore {
	return mr.Ks
}

// WalletDatastore returns the wallet datastore.
func (mr *MemRepo) WalletDatastore() Datastore {
	return mr.W
}

// ChainDatastore returns the chain datastore.
func (mr *MemRepo) ChainDatastore() Datastore {
	return mr.Chain
}

// ChainDatastore returns the chain datastore.
func (mr *MemRepo) MetaDatastore() Datastore {
	return mr.Meta
}

// Version returns the version of the repo.
func (mr *MemRepo) Version() uint {
	return mr.version
}

// Close deletes the temporary directories which hold staged piece data and
// sealed sectors.
func (mr *MemRepo) Close() error {
	return nil
}

// SetAPIAddr writes the address of the running API to memory.
func (mr *MemRepo) SetJsonrpcAPIAddr(addr string) error {
	mr.jsonrpcAddress = addr
	return nil
}

// SetAPIAddr writes the address of the running API to memory.
func (mr *MemRepo) SetRustfulAPIAddr(addr string) error {
	mr.rustfulAddress = addr
	return nil
}

// APIAddr reads the address of the running API from memory.
func (mr *MemRepo) APIAddr() (RpcAPI, error) {
	return RpcAPI{
		RustfulAPI: mr.rustfulAddress,
		JsonrpcAPI: mr.jsonrpcAddress,
	}, nil
}

func (mr *MemRepo) SetAPIToken(token []byte) error {
	if len(mr.token) == 0 {
		mr.token = token
	}
	return nil
}

// Path returns the default path.
func (mr *MemRepo) Path() (string, error) {
	return paths.GetRepoPath("")
}

// JournalPath returns a string to satisfy the repo interface.
func (mr *MemRepo) JournalPath() string {
	return "in_memory_filecoin_journal_path"
}

// Repo return the repo
func (mr *MemRepo) Repo() Repo {
	return mr
}