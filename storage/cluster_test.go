// Copyright 2024 HAProxy Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/haproxytech/client-native/v6/misc"
	"github.com/haproxytech/dataplaneapi/storagetype"
	"github.com/stretchr/testify/require"
)

func TestCommit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ClusterModeDataFileName)
	clusterStorage, err := NewClusterModeStorage(path)
	require.NoError(t, err)

	next := storagetype.ClusterModeData{
		Users:      getSetupUsers(),
		Generation: 1,
		Journal: storagetype.Journal{
			{
				ID:               "op-1",
				Kind:             storagetype.OpAdd,
				Username:         "user2",
				PasswordHash:     "$6$salt$hash",
				BaseGeneration:   0,
				ResultGeneration: 1,
				Status:           storagetype.StatusPersisted,
				Timestamp:        time.Now().UTC(),
			},
		},
	}
	require.NoError(t, clusterStorage.Commit(next))

	// in-memory state matches the committed document (deeply)
	require.Equal(t, next, clusterStorage.Current())

	// durable state survives a fresh load
	reloaded, err := NewClusterModeStorage(path)
	require.NoError(t, err)
	require.Equal(t, storagetype.StatusPersisted, reloaded.Current().Journal[0].Status)

	// file keeps restrictive permissions
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestCommitWriteFailureKeepsOldState(t *testing.T) {
	initial := storagetype.ClusterModeData{
		Users:      getSetupUsers(),
		Generation: 3,
	}
	backend := &fakeClusterBackend{data: initial}
	cs := &clusterModeStorageImpl{storage: backend, ClusterModeData: initial}

	next := storagetype.ClusterModeData{
		Users:      append(getSetupUsers(), userToAdd()),
		Generation: 4,
		Journal: storagetype.Journal{{
			ID: "op-fail", Kind: storagetype.OpAdd, ResultGeneration: 4, Status: storagetype.StatusPersisted,
		}},
	}
	backend.fail = true
	err := cs.Commit(next)
	var persistErr *PersistError
	require.ErrorAs(t, err, &persistErr)
	require.Equal(t, "op-fail", persistErr.OperationID)

	// old durable state is fully intact in memory
	require.Equal(t, initial, cs.Current())
	require.Equal(t, getSetupUsers(), cs.GetUsers())
}

func TestCommitAfterFailureSucceedsOnRetry(t *testing.T) {
	initial := storagetype.ClusterModeData{Users: getSetupUsers(), Generation: 1}
	backend := &fakeClusterBackend{data: initial, fail: true}
	cs := &clusterModeStorageImpl{storage: backend, ClusterModeData: initial}

	next := storagetype.ClusterModeData{Users: append(getSetupUsers(), userToAdd()), Generation: 2}
	require.Error(t, cs.Commit(next))

	backend.fail = false
	require.NoError(t, cs.Commit(next))
	require.Equal(t, next, cs.Current())
}

func TestCurrentIsDeepCopy(t *testing.T) {
	data := storagetype.ClusterModeData{
		Users:      getSetupUsers(),
		Generation: 2,
		Journal: storagetype.Journal{
			{ID: "op", Kind: storagetype.OpDelete, Status: storagetype.StatusPublished},
		},
	}
	cs := &clusterModeStorageImpl{ClusterModeData: data}

	view := cs.Current()
	view.Users[0].Name = "mutated"
	*view.Users[1].Password = "mutated"
	view.Journal[0].Status = storagetype.StatusPersisted
	view.Generation = 99

	again := cs.Current()
	require.Equal(t, "admin", again.Users[0].Name)
	require.Equal(t, "user1", *again.Users[1].Password)
	require.Equal(t, storagetype.StatusPublished, again.Journal[0].Status)
	require.Equal(t, uint64(2), again.Generation)
}

func TestLoadNormalizesLegacyGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ClusterModeDataFileName)
	fs := &fileStorage[storagetype.ClusterModeData]{path}
	require.NoError(t, fs.Store(storagetype.ClusterModeData{Users: getSetupUsers()})) // legacy shape, no generation

	clusterStorage, err := NewClusterModeStorage(path)
	require.NoError(t, err)
	require.NoError(t, clusterStorage.Load())
	require.Equal(t, uint64(1), clusterStorage.Current().Generation)

	// an empty legacy file stays at generation 0
	emptyPath := filepath.Join(t.TempDir(), ClusterModeDataFileName)
	emptyStorage, err := NewClusterModeStorage(emptyPath)
	require.NoError(t, err)
	require.NoError(t, emptyStorage.Load())
	require.Equal(t, uint64(0), emptyStorage.Current().Generation)
}

func TestReconcileFlipsPersistedEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ClusterModeDataFileName)
	fs := &fileStorage[storagetype.ClusterModeData]{path}
	require.NoError(t, fs.initFile())

	// legacy users without generation + one entry left "persisted" by a crash
	legacy := storagetype.ClusterModeData{
		Users: getSetupUsers(),
		Journal: storagetype.Journal{
			{ID: "op-old", Kind: storagetype.OpAdd, ResultGeneration: 1, Status: storagetype.StatusPublished},
			{ID: "op-new", Kind: storagetype.OpRotate, ResultGeneration: 2, Status: storagetype.StatusPersisted},
		},
	}
	require.NoError(t, fs.Store(legacy))

	clusterStorage, err := NewClusterModeStorage(path)
	require.NoError(t, err)

	data, err := clusterStorage.Reconcile()
	require.NoError(t, err)
	require.Equal(t, uint64(1), data.Generation) // legacy normalization
	for _, e := range data.Journal {
		require.Equal(t, storagetype.StatusPublished, e.Status, "entry %s not reconciled", e.ID)
	}

	// the reconciliation was durably rewritten
	reloaded, err := fs.Get()
	require.NoError(t, err)
	require.Equal(t, uint64(1), reloaded.Generation)
	for _, e := range reloaded.Journal {
		require.Equal(t, storagetype.StatusPublished, e.Status)
	}
}

func TestReconcileRewriteFailureStillReturnsNormalizedData(t *testing.T) {
	backend := &fakeClusterBackend{
		data: storagetype.ClusterModeData{
			Users:   getSetupUsers(),
			Journal: storagetype.Journal{{ID: "op", Status: storagetype.StatusPersisted}},
		},
		fail: true,
	}
	cs := &clusterModeStorageImpl{
		storage:         backend,
		ClusterModeData: backend.data,
	}
	data, err := cs.Reconcile()
	require.Error(t, err)
	require.Equal(t, uint64(1), data.Generation)
	require.Equal(t, storagetype.StatusPublished, data.Journal[0].Status)
	// in-memory state is normalized even though the rewrite failed
	require.Equal(t, data, cs.Current())
}

type fakeClusterBackend struct {
	data storagetype.ClusterModeData
	fail bool
}

func (f *fakeClusterBackend) Get() (storagetype.ClusterModeData, error) {
	return f.data, nil
}

func (f *fakeClusterBackend) Store(data storagetype.ClusterModeData) error {
	if f.fail {
		return errors.New("disk full")
	}
	f.data = data
	return nil
}

func getSetupUsers() storagetype.Users {
	return storagetype.Users{
		storagetype.User{
			Name:     "admin",
			Password: misc.StringP("admin"),
		},
		storagetype.User{
			Name:     "user1",
			Password: misc.StringP("user1"),
		},
		storagetype.User{
			Name:     "user2",
			Password: misc.StringP("user2"),
		},
	}
}

func userToAdd() storagetype.User {
	return storagetype.User{
		Name:     "useradded",
		Password: misc.StringP("useradded"),
		Insecure: misc.BoolP(true),
	}
}
