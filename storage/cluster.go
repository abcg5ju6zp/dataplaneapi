package storage

import (
	"fmt"
	"slices"
	"sync"

	"github.com/haproxytech/dataplaneapi/storagetype"
)

const (
	ClusterModeDataFileName = "cluster.json"
)

// PersistError marks a durable-write failure. The in-memory state is
// guaranteed unchanged when it is returned, so the caller may keep serving
// with the old snapshot and the client can safely retry the same operation.
type PersistError struct {
	OperationID string
	Err         error
}

func (e *PersistError) Error() string {
	return fmt.Sprintf("failed to persist API user operation %q: %v", e.OperationID, e.Err)
}

func (e *PersistError) Unwrap() error {
	return e.Err
}

// ClusterModeStorage persists dataplane-managed users in the dataplane
// storage file (historically cluster.json).
//
// The only mutation primitive is Commit: the complete next document is
// durably and atomically written first, and the in-memory state is swapped
// only after the write succeeds. In-memory state therefore never diverges
// from the durable state.
type ClusterModeStorage interface {
	// Load reads the storage file into memory.
	Load() error
	// Current returns a deep copy of the durable in-memory state.
	Current() storagetype.ClusterModeData
	// Commit atomically persists next and, on success, replaces the
	// in-memory state with it. On failure nothing in memory changes and a
	// *PersistError is returned.
	Commit(next storagetype.ClusterModeData) error
	// Reconcile normalizes a loaded document at startup: legacy files with
	// users but no generation get generation 1, and journal entries left in
	// "persisted" state by a crash between durable write and snapshot
	// publication are flipped to "published". When normalization changes the
	// document it is best-effort rewritten; the normalized data is returned
	// regardless of that rewrite's outcome, together with the rewrite error.
	Reconcile() (storagetype.ClusterModeData, error)
	// GetUsers returns the durable managed users.
	GetUsers() storagetype.Users
}

type clusterModeStorageImpl struct {
	ClusterModeData storagetype.ClusterModeData
	storage         Storage[storagetype.ClusterModeData]
	mu              sync.RWMutex
}

// NewClusterModeStorage creates a new clusterModeStorageImpl with initial configuration from a file path.
func NewClusterModeStorage(path string) (ClusterModeStorage, error) {
	fs := &fileStorage[storagetype.ClusterModeData]{path}
	if err := fs.initFile(); err != nil {
		return nil, err
	}
	clusterStorage, err := fs.Get()
	if err != nil {
		return nil, err
	}
	return &clusterModeStorageImpl{
		storage:         fs,
		ClusterModeData: clusterStorage,
	}, nil
}

func (cs *clusterModeStorageImpl) Load() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	data, err := cs.storage.Get()
	if err != nil {
		return err
	}
	cs.ClusterModeData = normalize(data)

	return nil
}

func (cs *clusterModeStorageImpl) Current() storagetype.ClusterModeData {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cloneData(cs.ClusterModeData)
}

func (cs *clusterModeStorageImpl) Commit(next storagetype.ClusterModeData) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if err := cs.storage.Store(next); err != nil {
		// Intentionally keep the previous in-memory state untouched: the
		// durable write is atomic (rename), and swap happens only after it
		// succeeds.
		return &PersistError{OperationID: lastOperationID(next), Err: err}
	}
	cs.ClusterModeData = cloneData(next)
	return nil
}

func (cs *clusterModeStorageImpl) Reconcile() (storagetype.ClusterModeData, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	normalized := normalize(cs.ClusterModeData)
	changed := !equalData(cs.ClusterModeData, normalized)
	if changed {
		if err := cs.storage.Store(normalized); err != nil {
			// Keep the normalized in-memory state even if the rewrite failed:
			// auth still works and the next successful commit converges the
			// file.
			cs.ClusterModeData = normalized
			return cloneData(normalized), err
		}
		cs.ClusterModeData = normalized
	}
	return cloneData(normalized), nil
}

func (cs *clusterModeStorageImpl) GetUsers() storagetype.Users {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cloneUsers(cs.ClusterModeData.Users)
}

// normalize applies backward-compatible rules to a loaded document.
func normalize(data storagetype.ClusterModeData) storagetype.ClusterModeData {
	out := cloneData(data)
	if out.Generation == 0 && len(out.Users) > 0 {
		// Legacy file written before generations existed: its materialized
		// user set is generation 1.
		out.Generation = 1
	}
	for i := range out.Journal {
		if out.Journal[i].Status == storagetype.StatusPersisted {
			// A durable entry that survived a crash means its generation is
			// materialized in Users; the startup rebuild publishes it.
			out.Journal[i].Status = storagetype.StatusPublished
		}
	}
	return out
}

func lastOperationID(data storagetype.ClusterModeData) string {
	if len(data.Journal) == 0 {
		return ""
	}
	return data.Journal[len(data.Journal)-1].ID
}

func equalData(a, b storagetype.ClusterModeData) bool {
	if a.Generation != b.Generation || len(a.Users) != len(b.Users) || len(a.Journal) != len(b.Journal) {
		return false
	}
	for i := range a.Journal {
		if a.Journal[i].Status != b.Journal[i].Status {
			return false
		}
	}
	return slices.EqualFunc(a.Users, b.Users, func(x, y storagetype.User) bool {
		return x.Name == y.Name && strPtrEq(x.Password, y.Password) && boolPtrEq(x.Insecure, y.Insecure)
	})
}

func strPtrEq(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func boolPtrEq(a, b *bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func cloneUsers(users storagetype.Users) storagetype.Users {
	if users == nil {
		return nil
	}
	out := make(storagetype.Users, len(users))
	for i, u := range users {
		out[i] = u
		if u.Insecure != nil {
			v := *u.Insecure
			out[i].Insecure = &v
		}
		if u.Password != nil {
			v := *u.Password
			out[i].Password = &v
		}
	}
	return out
}

func cloneData(data storagetype.ClusterModeData) storagetype.ClusterModeData {
	out := storagetype.ClusterModeData{
		Users:      cloneUsers(data.Users),
		Generation: data.Generation,
	}
	if data.Journal != nil {
		out.Journal = slices.Clone(data.Journal)
	}
	if data.LastFailure != nil {
		v := *data.LastFailure
		out.LastFailure = &v
	}
	return out
}
