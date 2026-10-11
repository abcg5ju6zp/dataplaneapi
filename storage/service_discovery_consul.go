package storage

import (
	"slices"
	"sync"

	"github.com/haproxytech/client-native/v6/models"
	"github.com/haproxytech/dataplaneapi/storagetype"
)

const (
	ConsulFileName = "service_discovery/consul.json"
)

type SDConsulStorage interface {
	Consul

	Load() error
	Store() error
	Status() StatusReport
}

type Consul interface {
	// GetConsuls does not load the consuls from the storage. Use Load() to load the them if needed.
	GetConsuls() storagetype.Consuls
	// AddConsulsAndStore adds a list of consuls to the storage and stores in the storage file.
	AddConsulsAndStore(consuls storagetype.Consuls) error
	// AddConsulAndStore adds a new consul to the storage and stores in the storage file.
	AddConsulAndStore(consul *models.Consul) error
	// RemoveConsulAndStore removes a consul from the storage and stores in the storage file.
	RemoveConsulAndStore(consul *models.Consul) error
	// ReplaceAllConsulsAndStore replaces the list of consuls in the storage and stores in the storage file.
	ReplaceAllConsulsAndStore(consuls storagetype.Consuls) error
}

type consulStorageImpl struct {
	ConsulData storagetype.ConsulData
	storage    Storage[storagetype.ConsulData]
	mu         sync.RWMutex
}

// NewSDConsulStorage creates a new consulStorageImpl with initial configuration from a file path.
// It never fails on a corrupt state file: inspect Status for the independent
// recovery conclusion (recovered / read-only isolated / unavailable).
func NewSDConsulStorage(path string) (SDConsulStorage, error) {
	fs := newFileStorage[storagetype.ConsulData](path)
	consulData, _ := fs.Get()
	return &consulStorageImpl{
		storage:    fs,
		ConsulData: consulData,
	}, nil
}

func (cs *consulStorageImpl) Status() StatusReport {
	return cs.storage.Status()
}

func (cs *consulStorageImpl) GetConsuls() storagetype.Consuls {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.ConsulData.Consuls
}

func (cs *consulStorageImpl) Load() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	consul, _ := cs.storage.Get()
	cs.ConsulData = consul

	return nil
}

func (cs *consulStorageImpl) Store() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	return cs.commit(cs.ConsulData.Consuls)
}

func (cs *consulStorageImpl) AddConsulAndStore(consul *models.Consul) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	candidate := append(slices.Clone(cs.ConsulData.Consuls), consul)
	return cs.commit(candidate)
}

func (cs *consulStorageImpl) AddConsulsAndStore(consuls storagetype.Consuls) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	candidate := append(slices.Clone(cs.ConsulData.Consuls), consuls...)
	return cs.commit(candidate)
}

func (cs *consulStorageImpl) ReplaceAllConsulsAndStore(consuls storagetype.Consuls) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	return cs.commit(slices.Clone(consuls))
}

func (cs *consulStorageImpl) RemoveConsulAndStore(consul *models.Consul) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	candidate := make(storagetype.Consuls, 0, len(cs.ConsulData.Consuls))
	for _, c := range cs.ConsulData.Consuls {
		if c.Name != consul.Name {
			candidate = append(candidate, c)
		}
	}
	return cs.commit(candidate)
}

// commit stores the candidate generation and swaps the in-memory active
// object only after the durable write is verified. On failure the active
// object converges with the engine's authoritative view (e.g. the
// restored last known good generation); a failed write never leaves a
// pending mutation visible.
func (cs *consulStorageImpl) commit(consuls storagetype.Consuls) error {
	candidate := storagetype.ConsulData{Consuls: consuls}
	if err := cs.storage.Store(candidate); err != nil {
		cs.ConsulData = cs.storage.Active()
		return err
	}
	cs.ConsulData = candidate
	return nil
}
