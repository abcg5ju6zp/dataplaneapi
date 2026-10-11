// Copyright 2026 HAProxy Technologies
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

package configuration

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/haproxytech/client-native/v6/config-parser/types"
	"github.com/stretchr/testify/require"

	"github.com/haproxytech/dataplaneapi/storage"
	"github.com/haproxytech/dataplaneapi/storagetype"
)

var fixedNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// fakeClusterStorage is an in-memory ClusterModeStorage that deep-copies like
// the real file backend and can be forced to fail.
type fakeClusterStorage struct {
	mu             sync.Mutex
	data           storagetype.ClusterModeData
	fail           bool
	reconcileErr   error
	commits        []storagetype.ClusterModeData
	businessWrites int
}

func (f *fakeClusterStorage) Load() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return nil
}

func (f *fakeClusterStorage) Current() storagetype.ClusterModeData {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fakeClone(f.data)
}

func (f *fakeClusterStorage) Commit(next storagetype.ClusterModeData) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return &storage.PersistError{OperationID: lastEntryID(next), Err: errors.New("disk full")}
	}
	f.commits = append(f.commits, fakeClone(next))
	if len(next.Journal) > 0 && next.Journal[len(next.Journal)-1].Status == storagetype.StatusPersisted {
		f.businessWrites++
	}
	f.data = fakeClone(next)
	return nil
}

func (f *fakeClusterStorage) Reconcile() (storagetype.ClusterModeData, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	normalized := fakeClone(f.data)
	if normalized.Generation == 0 && len(normalized.Users) > 0 {
		normalized.Generation = 1
	}
	for i := range normalized.Journal {
		if normalized.Journal[i].Status == storagetype.StatusPersisted {
			normalized.Journal[i].Status = storagetype.StatusPublished
		}
	}
	f.data = normalized
	return normalized, f.reconcileErr
}

func (f *fakeClusterStorage) GetUsers() storagetype.Users {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fakeClone(f.data).Users
}

func (f *fakeClusterStorage) businessWriteCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.businessWrites
}

func (f *fakeClusterStorage) commitCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.commits)
}

func fakeClone(data storagetype.ClusterModeData) storagetype.ClusterModeData {
	out := storagetype.ClusterModeData{Generation: data.Generation}
	if data.Users != nil {
		out.Users = make(storagetype.Users, len(data.Users))
		for i, u := range data.Users {
			out.Users[i] = u
			if u.Password != nil {
				v := *u.Password
				out.Users[i].Password = &v
			}
			if u.Insecure != nil {
				v := *u.Insecure
				out.Users[i].Insecure = &v
			}
		}
	}
	if data.Journal != nil {
		out.Journal = append(storagetype.Journal(nil), data.Journal...)
	}
	if data.LastFailure != nil {
		v := *data.LastFailure
		out.LastFailure = &v
	}
	return out
}

func lastEntryID(data storagetype.ClusterModeData) string {
	if len(data.Journal) == 0 {
		return ""
	}
	return data.Journal[len(data.Journal)-1].ID
}

// setupUsersStore wires the global store to a fake storage with the given
// durable state, publishing its initial snapshot.
func setupUsersStore(t *testing.T, data storagetype.ClusterModeData) (*Users, *fakeClusterStorage) {
	t.Helper()
	st := &fakeClusterStorage{data: data}
	store := GetUsersStore()
	store.storage = st
	store.now = func() time.Time { return fixedNow }
	store.hooks = commitHooks{}
	store.lastFailure.Store(nil)
	store.current.Store(buildSnapshot(data.Generation, data.Users, configUsers(Get().Users)))
	t.Cleanup(func() {
		store.storage = nil
		store.hooks = commitHooks{}
		store.lastFailure.Store(nil)
		store.current.Store(nil)
	})
	return store, st
}

func hashedPassword(t *testing.T, plain string) string {
	t.Helper()
	h, err := hashPassword(plain)
	require.NoError(t, err)
	require.Contains(t, h, "$6$")
	return h
}

func managedUsersData(users ...storagetype.User) storagetype.ClusterModeData {
	return storagetype.ClusterModeData{Users: storagetype.Users(users), Generation: uint64(len(users))}
}

func strP(v string) *string { return &v }

// TestCommitAddRotateDelete exercises the single commit rule for all three
// change kinds: generation advances, hashes are persisted, journal converges
// to published.
func TestCommitAddRotateDelete(t *testing.T) {
	store, st := setupUsersStore(t, storagetype.ClusterModeData{})

	addRes, err := store.Commit(APIUserCommitInput{
		OperationID: "op-add", Kind: APIUserAdd, Username: "bob", Password: "bobpass", BaseGeneration: 0,
	})
	require.NoError(t, err)
	require.Equal(t, uint64(1), addRes.Generation)
	require.Equal(t, StatusCommitted, addRes.Status)

	// the first durable write carried "persisted", the rewrite "published"
	require.Equal(t, storagetype.StatusPersisted, st.commits[0].Journal[0].Status)
	require.Equal(t, storagetype.StatusPublished, st.data.Journal[0].Status)

	_, err = AuthenticateUser("bob", "bobpass")
	require.NoError(t, err)

	rotateRes, err := store.Commit(APIUserCommitInput{
		OperationID: "op-rotate", Kind: APIUserRotate, Username: "bob", Password: "bobnewpass", BaseGeneration: 1,
	})
	require.NoError(t, err)
	require.Equal(t, uint64(2), rotateRes.Generation)
	_, err = AuthenticateUser("bob", "bobnewpass")
	require.NoError(t, err)
	_, err = AuthenticateUser("bob", "bobpass")
	require.Error(t, err)

	deleteRes, err := store.Commit(APIUserCommitInput{
		OperationID: "op-delete", Kind: APIUserDelete, Username: "bob", BaseGeneration: 2,
	})
	require.NoError(t, err)
	require.Equal(t, uint64(3), deleteRes.Generation)
	require.Empty(t, st.data.Users)
	_, err = AuthenticateUser("bob", "bobnewpass")
	require.Error(t, err)

	// no plaintext password ever reaches the durable document
	for _, password := range []string{"bobpass", "bobnewpass"} {
		for _, doc := range st.commits {
			raw, err := json.Marshal(doc)
			require.NoError(t, err)
			require.NotContains(t, string(raw), password)
		}
	}
}

func TestCommitStaleGenerationRejected(t *testing.T) {
	store, st := setupUsersStore(t, storagetype.ClusterModeData{})
	_, err := store.Commit(APIUserCommitInput{
		OperationID: "op-1", Kind: APIUserAdd, Username: "u1", Password: "p1", BaseGeneration: 0,
	})
	require.NoError(t, err)
	writes := st.businessWriteCount()

	_, err = store.Commit(APIUserCommitInput{
		OperationID: "op-old", Kind: APIUserAdd, Username: "u2", Password: "p2", BaseGeneration: 0,
	})
	require.ErrorIs(t, err, ErrStaleGeneration)
	require.Equal(t, writes, st.businessWriteCount())
	require.Len(t, st.data.Users, 1)
}

func TestCommitDuplicateUserRejected(t *testing.T) {
	data := managedUsersData(storagetype.User{Name: "bob", Password: strP(hashedPassword(t, "x"))})
	store, st := setupUsersStore(t, data)

	_, err := store.Commit(APIUserCommitInput{
		OperationID: "op-dup", Kind: APIUserAdd, Username: "bob", Password: "p", BaseGeneration: 1,
	})
	require.ErrorIs(t, err, ErrUserAlreadyExists)
	require.Equal(t, 0, st.businessWriteCount())
}

func TestCommitConfigFileUserCollisions(t *testing.T) {
	cfg := Get()
	saved := cfg.Users
	cfg.Users = []User{{Name: "root", Password: "rootpw", Insecure: true}}
	t.Cleanup(func() { cfg.Users = saved })

	store, st := setupUsersStore(t, storagetype.ClusterModeData{})
	// setupUsersStore built its snapshot before cfg.Users was visible; rebuild
	// with the overlay the same way Init does.
	store.current.Store(buildSnapshot(0, nil, configUsers(cfg.Users)))

	_, err := store.Commit(APIUserCommitInput{
		OperationID: "op-add-root", Kind: APIUserAdd, Username: "root", Password: "p", BaseGeneration: 0,
	})
	require.ErrorIs(t, err, ErrConfigUserCollision)

	_, err = store.Commit(APIUserCommitInput{
		OperationID: "op-del-root", Kind: APIUserDelete, Username: "root", BaseGeneration: 0,
	})
	require.ErrorIs(t, err, ErrCannotManageConfigUser)

	_, err = store.Commit(APIUserCommitInput{
		OperationID: "op-rot-root", Kind: APIUserRotate, Username: "root", Password: "p", BaseGeneration: 0,
	})
	require.ErrorIs(t, err, ErrCannotManageConfigUser)
	require.Equal(t, 0, st.businessWriteCount())

	// config user still authenticates
	_, err = AuthenticateUser("root", "rootpw")
	require.NoError(t, err)
}

func TestDeleteUnknownManagedUser(t *testing.T) {
	store, _ := setupUsersStore(t, storagetype.ClusterModeData{})
	_, err := store.Commit(APIUserCommitInput{
		OperationID: "op-del", Kind: APIUserDelete, Username: "ghost", BaseGeneration: 0,
	})
	require.ErrorIs(t, err, ErrManagedUserNotFound)
}

// TestReplayDoesNotRotateAgain is the core idempotency guarantee: a retried
// rotate returns the original result and never changes the password twice.
func TestReplayDoesNotRotateAgain(t *testing.T) {
	data := managedUsersData(storagetype.User{Name: "alice", Password: strP(hashedPassword(t, "oldpass"))})
	store, st := setupUsersStore(t, data)

	first, err := store.Commit(APIUserCommitInput{
		OperationID: "op-rotate", Kind: APIUserRotate, Username: "alice",
		Password: "newpass", BaseGeneration: 1,
	})
	require.NoError(t, err)
	require.Equal(t, StatusCommitted, first.Status)
	commitsAfterFirst := st.commitCount()
	storedHash := *managedUserByName(st.data.Users, "alice").Password

	// response lost, identical retry (base generation intentionally stale:
	// replay must not be rejected by the generation check)
	replay, err := store.Commit(APIUserCommitInput{
		OperationID: "op-rotate", Kind: APIUserRotate, Username: "alice",
		Password: "newpass", BaseGeneration: 1,
	})
	require.NoError(t, err)
	require.Equal(t, StatusReplayed, replay.Status)
	require.Equal(t, first.Generation, replay.Generation)
	require.Equal(t, commitsAfterFirst, st.commitCount(), "replay must not write again")
	require.Equal(t, storedHash, *managedUserByName(st.data.Users, "alice").Password)

	// same id, different password / kind / username is a conflict
	_, err = store.Commit(APIUserCommitInput{
		OperationID: "op-rotate", Kind: APIUserRotate, Username: "alice",
		Password: "different", BaseGeneration: 1,
	})
	require.ErrorIs(t, err, ErrOperationIDConflict)
	_, err = store.Commit(APIUserCommitInput{
		OperationID: "op-rotate", Kind: APIUserDelete, Username: "alice", BaseGeneration: 1,
	})
	require.ErrorIs(t, err, ErrOperationIDConflict)
	_, err = store.Commit(APIUserCommitInput{
		OperationID: "op-rotate", Kind: APIUserAdd, Username: "alice", Password: "newpass", BaseGeneration: 1,
	})
	require.ErrorIs(t, err, ErrOperationIDConflict)
}

// TestReplayRepairsUnpublishedSnapshot covers the "durable success, snapshot
// not published" state: retry rebuilds the snapshot from the durable version.
func TestReplayRepairsUnpublishedSnapshot(t *testing.T) {
	store, st := setupUsersStore(t, storagetype.ClusterModeData{})
	var hookRan atomic.Bool
	store.hooks = commitHooks{
		afterDurablePersist: func(next storagetype.ClusterModeData) error {
			if hookRan.CompareAndSwap(false, true) {
				return errors.New("simulated crash window")
			}
			return nil
		},
	}

	_, err := store.Commit(APIUserCommitInput{
		OperationID: "op-add", Kind: APIUserAdd, Username: "bob", Password: "bobpass", BaseGeneration: 0,
	})
	var publishErr *PublishError
	require.ErrorAs(t, err, &publishErr)

	// old generation stays live, new credentials are not yet active
	require.Equal(t, uint64(0), store.current.Load().generation)
	_, err = AuthenticateUser("bob", "bobpass")
	require.Error(t, err)
	require.Equal(t, storagetype.StatusPersisted, st.data.Journal[0].Status)

	// same operation retried: original result plus snapshot repair
	replay, err := store.Commit(APIUserCommitInput{
		OperationID: "op-add", Kind: APIUserAdd, Username: "bob", Password: "bobpass", BaseGeneration: 0,
	})
	require.NoError(t, err)
	require.Equal(t, StatusReplayed, replay.Status)
	require.Equal(t, uint64(1), replay.Generation)
	require.Equal(t, uint64(1), store.current.Load().generation)
	_, err = AuthenticateUser("bob", "bobpass")
	require.NoError(t, err)
	require.Equal(t, storagetype.StatusPublished, st.data.Journal[0].Status)
}

// TestPersistFailureKeepsOldCredentials covers the durable-write failure:
// the same operation retried after recovery commits normally.
func TestPersistFailureKeepsOldCredentials(t *testing.T) {
	data := managedUsersData(storagetype.User{Name: "alice", Password: strP(hashedPassword(t, "alicepass"))})
	store, st := setupUsersStore(t, data)
	st.fail = true

	_, err := store.Commit(APIUserCommitInput{
		OperationID: "op-add", Kind: APIUserAdd, Username: "bob", Password: "bobpass", BaseGeneration: 1,
	})
	var persistErr *storage.PersistError
	require.ErrorAs(t, err, &persistErr)

	// old snapshot and credentials stay valid
	require.Equal(t, uint64(1), store.current.Load().generation)
	_, err = AuthenticateUser("alice", "alicepass")
	require.NoError(t, err)
	lf := store.lastFailure.Load()
	require.NotNil(t, lf)
	require.Equal(t, storagetype.PhasePersist, lf.Phase)
	require.NotContains(t, lf.Message, "bobpass")

	// retry the same operation after the storage is writable again
	st.fail = false
	res, err := store.Commit(APIUserCommitInput{
		OperationID: "op-add", Kind: APIUserAdd, Username: "bob", Password: "bobpass", BaseGeneration: 1,
	})
	require.NoError(t, err)
	require.Equal(t, StatusCommitted, res.Status)
	require.Equal(t, uint64(2), res.Generation)
	_, err = AuthenticateUser("bob", "bobpass")
	require.NoError(t, err)

	// the earlier failure was folded into the durable diagnostics, then the
	// in-memory indicator cleared once the published rewrite landed
	require.Nil(t, store.lastFailure.Load())
	require.NotNil(t, st.data.LastFailure)
	require.Equal(t, storagetype.PhasePersist, st.data.LastFailure.Phase)
	raw, err := json.Marshal(st.data)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "bobpass")
}

// TestInitReconcilesAfterRestart simulates a restart with a legacy file whose
// last durable generation was never marked published.
func TestInitReconcilesAfterRestart(t *testing.T) {
	insecure := true
	legacy := storagetype.ClusterModeData{
		Users: storagetype.Users{
			{Name: "alice", Password: strP("alicelegacy"), Insecure: &insecure},
		},
		Journal: storagetype.Journal{
			{ID: "op-unpublished", Kind: storagetype.OpAdd, Username: "alice",
				BaseGeneration: 0, ResultGeneration: 1, Status: storagetype.StatusPersisted, Timestamp: fixedNow},
		},
	}
	st := &fakeClusterStorage{data: legacy}
	cfg := Get()
	savedStorage := cfg.clusterModeStorage
	savedUsers := cfg.Users
	cfg.clusterModeStorage = st
	cfg.Users = nil
	t.Cleanup(func() {
		cfg.clusterModeStorage = savedStorage
		cfg.Users = savedUsers
	})

	store := GetUsersStore()
	store.storage = nil
	store.hooks = commitHooks{}
	store.lastFailure.Store(nil)
	require.NoError(t, store.Init())
	t.Cleanup(func() { store.current.Store(nil) })

	snap := store.current.Load()
	require.Equal(t, uint64(1), snap.generation)
	require.Equal(t, storagetype.StatusPublished, st.data.Journal[0].Status)
	_, err := AuthenticateUser("alice", "alicelegacy")
	require.NoError(t, err)
}

// TestConcurrentChangesSerializeByGeneration runs concurrent adds against a
// storm of auth requests; every change is serialized and no generation is
// lost. Run with -race.
func TestConcurrentChangesSerializeByGeneration(t *testing.T) {
	store, _ := setupUsersStore(t, storagetype.ClusterModeData{})

	const workers = 30
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("user%02d", i)
			password := fmt.Sprintf("pass%02d", i)
			for {
				generation := store.current.Load().generation
				_, err := store.Commit(APIUserCommitInput{
					OperationID: uuid.NewString(),
					Kind:        APIUserAdd,
					Username:    name,
					Password:    password,
					// each logical add has a stable name; a rejected stale
					// attempt is retried with a fresh operation id
					BaseGeneration: generation,
				})
				if err == nil {
					return
				}
				if !errors.Is(err, ErrStaleGeneration) {
					errCh <- err
					return
				}
			}
		}(i)
	}

	authDone := make(chan struct{})
	go func() {
		defer close(authDone)
		for range workers * 20 {
			_, _ = AuthenticateUser("user00", "pass00")
			_, _ = AuthenticateUser("nobody", "x")
		}
	}()

	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
	<-authDone

	require.Equal(t, uint64(workers), store.current.Load().generation)
	require.Len(t, store.current.Load().users, workers)
}

func TestDisabledDeployment(t *testing.T) {
	store := GetUsersStore()
	store.storage = nil
	t.Cleanup(func() { store.current.Store(nil) })
	store.current.Store(buildSnapshot(0, nil, []types.User{{Name: "cfg", Password: "cfgpw", IsInsecure: true}}))

	require.False(t, store.Enabled())
	_, err := store.Commit(APIUserCommitInput{
		OperationID: "op", Kind: APIUserAdd, Username: "u", Password: "p", BaseGeneration: 0,
	})
	require.ErrorIs(t, err, ErrAPIUsersDisabled)
	_, err = AuthenticateUser("cfg", "cfgpw")
	require.NoError(t, err)
}

// TestReloadOverlayKeepsManagedGeneration verifies a config-file reload only
// republished the overlay without touching durable users or generation.
func TestReloadOverlayKeepsManagedGeneration(t *testing.T) {
	cfg := Get()
	saved := cfg.Users
	cfg.Users = []User{{Name: "root", Password: "rootpw", Insecure: true}}
	t.Cleanup(func() { cfg.Users = saved })

	store, st := setupUsersStore(t, storagetype.ClusterModeData{})
	_, err := store.Commit(APIUserCommitInput{
		OperationID: "op-add", Kind: APIUserAdd, Username: "bob", Password: "bobpass", BaseGeneration: 0,
	})
	require.NoError(t, err)
	bobHash := *managedUserByName(st.data.Users, "bob").Password

	cfg.Users = append(cfg.Users, User{Name: "extra", Password: "extrapw", Insecure: true})
	require.NoError(t, store.ReloadOverlay())

	snap := store.current.Load()
	require.Equal(t, uint64(1), snap.generation)
	require.Equal(t, bobHash, *managedUserByName(snap.managed, "bob").Password)
	_, err = AuthenticateUser("extra", "extrapw")
	require.NoError(t, err)
	_, err = AuthenticateUser("bob", "bobpass")
	require.NoError(t, err)
}

func TestJournalBoundedAndAgedRetry(t *testing.T) {
	store, st := setupUsersStore(t, storagetype.ClusterModeData{})

	firstOpID := ""
	const total = storagetype.JournalLimit + 5
	for i := range total {
		name := fmt.Sprintf("u%03d", i)
		opID := fmt.Sprintf("op-%03d", i)
		if i == 0 {
			firstOpID = opID
		}
		_, err := store.Commit(APIUserCommitInput{
			OperationID: opID, Kind: APIUserAdd, Username: name,
			Password: fmt.Sprintf("p%03d", i), BaseGeneration: uint64(i),
		})
		require.NoError(t, err)
	}
	require.Len(t, st.data.Journal, storagetype.JournalLimit)
	require.Nil(t, st.data.FindOperation(firstOpID))

	writes := st.businessWriteCount()
	// aged-out retry looks like a new operation: it can never double-apply
	_, err := store.Commit(APIUserCommitInput{
		OperationID: firstOpID, Kind: APIUserAdd, Username: "u000",
		Password: "p000", BaseGeneration: 0,
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrStaleGeneration) || errors.Is(err, ErrUserAlreadyExists))
	require.Equal(t, writes, st.businessWriteCount())
}

// TestReplayAfterDeleteAndReadd verifies an old replay never revives a user or
// overwrites a newer credential.
func TestReplayAfterDeleteAndReadd(t *testing.T) {
	store, st := setupUsersStore(t, storagetype.ClusterModeData{})

	_, err := store.Commit(APIUserCommitInput{
		OperationID: "op-add1", Kind: APIUserAdd, Username: "bob", Password: "pass1", BaseGeneration: 0,
	})
	require.NoError(t, err)
	_, err = store.Commit(APIUserCommitInput{
		OperationID: "op-del", Kind: APIUserDelete, Username: "bob", BaseGeneration: 1,
	})
	require.NoError(t, err)
	_, err = store.Commit(APIUserCommitInput{
		OperationID: "op-add2", Kind: APIUserAdd, Username: "bob", Password: "pass2", BaseGeneration: 2,
	})
	require.NoError(t, err)
	currentHash := *managedUserByName(st.data.Users, "bob").Password

	replay, err := store.Commit(APIUserCommitInput{
		OperationID: "op-add1", Kind: APIUserAdd, Username: "bob", Password: "pass1", BaseGeneration: 0,
	})
	require.NoError(t, err)
	require.Equal(t, StatusReplayed, replay.Status)
	require.Equal(t, uint64(1), replay.Generation)
	// current credential untouched, old password still invalid
	require.Equal(t, currentHash, *managedUserByName(st.data.Users, "bob").Password)
	_, err = AuthenticateUser("bob", "pass1")
	require.Error(t, err)
	_, err = AuthenticateUser("bob", "pass2")
	require.NoError(t, err)
}

func TestListAndGet(t *testing.T) {
	data := managedUsersData(storagetype.User{Name: "alice", Password: strP(hashedPassword(t, "x"))})
	store, _ := setupUsersStore(t, data)

	view := store.List()
	require.Equal(t, uint64(1), view.Generation)
	require.Equal(t, "alice", view.Users[0].Username)
	require.Equal(t, "managed", view.Users[0].Source)

	got, ok := store.Get("alice")
	require.True(t, ok)
	require.Equal(t, "managed", got.Source)
	_, ok = store.Get("nobody")
	require.False(t, ok)
}
