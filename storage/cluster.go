package storage

import (
	"slices"
	"sync"

	"github.com/haproxytech/dataplaneapi/storagetype"
)

const (
	ClusterModeDataFileName = "cluster.json"
)

// ClusterModeStorage persists dataplane-managed users in the dataplane storage
// file (historically cluster.json).
type ClusterModeStorage interface {
	Users

	Load() error
	Store() error
	Status() StatusReport
}

type Users interface {
	// GetUsers does not load the users from the storage. Use Load() to load the users if needed.
	GetUsers() storagetype.Users
	// AddUsersAndStore adds a list of users to the storage and stores in the storage file.
	AddUsersAndStore(users storagetype.Users) error
	// AddUserAndStore adds a new user to the storage and stores in the storage file.
	AddUserAndStore(user storagetype.User) error
	// RemoveUserAndStore removes a user from the storage and stores in the storage file.
	RemoveUserAndStore(user storagetype.User) error
	// ReplaceAllUsersAndStore replaces the list of users in the storage and stores in the storage file.
	ReplaceAllUsersAndStore(users storagetype.Users) error
}

type clusterModeStorageImpl struct {
	ClusterModeData storagetype.ClusterModeData
	storage         Storage[storagetype.ClusterModeData]
	mu              sync.RWMutex
}

// NewClusterModeStorage creates a new clusterModeStorageImpl with initial configuration from a file path.
// It never fails on a corrupt state file: inspect Status for the independent
// recovery conclusion (recovered / read-only isolated / unavailable).
func NewClusterModeStorage(path string) (ClusterModeStorage, error) {
	fs := newFileStorage[storagetype.ClusterModeData](path)
	clusterData, _ := fs.Get()
	return &clusterModeStorageImpl{
		storage:         fs,
		ClusterModeData: clusterData,
	}, nil
}

func (cs *clusterModeStorageImpl) Status() StatusReport {
	return cs.storage.Status()
}

func (cs *clusterModeStorageImpl) Load() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	data, _ := cs.storage.Get()
	cs.ClusterModeData = data

	return nil
}

func (cs *clusterModeStorageImpl) Store() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	return cs.commit(cs.ClusterModeData.Users)
}

func (cs *clusterModeStorageImpl) GetUsers() storagetype.Users {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.ClusterModeData.Users
}

func (cs *clusterModeStorageImpl) AddUserAndStore(user storagetype.User) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	candidate := append(slices.Clone(cs.ClusterModeData.Users), user)
	return cs.commit(candidate)
}

func (cs *clusterModeStorageImpl) AddUsersAndStore(users storagetype.Users) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	candidate := append(slices.Clone(cs.ClusterModeData.Users), users...)
	return cs.commit(candidate)
}

func (cs *clusterModeStorageImpl) ReplaceAllUsersAndStore(users storagetype.Users) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	return cs.commit(slices.Clone(users))
}

func (cs *clusterModeStorageImpl) RemoveUserAndStore(user storagetype.User) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	candidate := make(storagetype.Users, 0, len(cs.ClusterModeData.Users))
	for _, u := range cs.ClusterModeData.Users {
		if u.Name != user.Name {
			candidate = append(candidate, u)
		}
	}
	return cs.commit(candidate)
}

// commit stores the candidate generation and swaps the in-memory active
// object only after the durable write is verified. On failure the active
// object converges with the engine's authoritative view (e.g. the
// restored last known good generation); a failed write never leaves a
// pending mutation visible.
func (cs *clusterModeStorageImpl) commit(users storagetype.Users) error {
	candidate := storagetype.ClusterModeData{Users: users}
	if err := cs.storage.Store(candidate); err != nil {
		cs.ClusterModeData = cs.storage.Active()
		return err
	}
	cs.ClusterModeData = candidate
	return nil
}
