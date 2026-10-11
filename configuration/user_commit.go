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
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/GehirnInc/crypt"

	"github.com/haproxytech/dataplaneapi/log"
	"github.com/haproxytech/dataplaneapi/storagetype"
)

// APIUserKind is the kind of an API user change.
type APIUserKind string

const (
	APIUserAdd    APIUserKind = "add"
	APIUserDelete APIUserKind = "delete"
	APIUserRotate APIUserKind = "rotate_password"
)

// API user change statuses reported to clients.
const (
	StatusCommitted = "committed"
	StatusReplayed  = "replayed"
)

// APIUserCommitInput is one add/delete/rotate request. The plaintext Password
// is only carried for add/rotate; it is hashed before persistence and must
// never be logged.
type APIUserCommitInput struct {
	OperationID    string
	Kind           APIUserKind
	Username       string
	Password       string
	BaseGeneration uint64
}

// APIUserCommitResult is the stable response of a change: a retried
// operation returns the same result with Status "replayed".
type APIUserCommitResult struct {
	OperationID string
	Kind        APIUserKind
	Username    string
	Generation  uint64
	Status      string
}

// APIUserView describes one user without any password material.
type APIUserView struct {
	Username string
	// Source is "managed" for users from the dataplane storage file and
	// "config" for users provided by the configuration file / userlist.
	Source string
}

// APIUsersView is the managed user set at one generation, plus the users
// provided by configuration (which cannot be managed through the API).
type APIUsersView struct {
	Generation  uint64
	Users       []APIUserView
	LastFailure *APIUserFailureView
}

// APIUserFailureView is the most recent diagnosable failure; it never
// contains passwords or hashes.
type APIUserFailureView struct {
	OperationID string
	Phase       storagetype.FailurePhase
	Message     string
	Generation  uint64
	Timestamp   time.Time
}

var (
	// ErrAPIUsersDisabled is returned on deployments without dataplane
	// storage loaded; authentication from configuration sources still works.
	ErrAPIUsersDisabled = errors.New("API user management is not enabled in this deployment")
	// ErrStaleGeneration means the request was based on a user-set generation
	// that is no longer current; the client must re-read the current
	// generation and retry.
	ErrStaleGeneration = errors.New("stale user-set generation")
	// ErrOperationIDConflict means an operation with the same id was already
	// persisted with different, detectable parameters.
	ErrOperationIDConflict = errors.New("operation id was already used with different parameters")
	// ErrUserAlreadyExists means a managed user with the name already exists.
	ErrUserAlreadyExists = errors.New("user already exists")
	// ErrConfigUserCollision means the name is already provided by the
	// configuration file and therefore cannot be added as a managed user.
	ErrConfigUserCollision = errors.New("user with this name is already defined in the configuration file")
	// ErrCannotManageConfigUser means delete/rotate targeted a configuration
	// file user, which the API cannot modify.
	ErrCannotManageConfigUser = errors.New("user is defined in the configuration file and cannot be managed through the API")
	// ErrManagedUserNotFound means delete/rotate targeted an unknown managed user.
	ErrManagedUserNotFound = errors.New("managed user not found")
)

// PublishError marks a change whose durable write succeeded but whose active
// snapshot could not be published. The old snapshot keeps serving; retrying
// the same operation repairs the snapshot.
type PublishError struct {
	OperationID string
	Err         error
}

func (e *PublishError) Error() string {
	return fmt.Sprintf("API user operation %q was persisted but the active snapshot was not published: %v", e.OperationID, e.Err)
}

func (e *PublishError) Unwrap() error { return e.Err }

// Enabled reports whether API user management is available (dataplane
// storage loaded).
func (u *Users) Enabled() bool {
	return u.storage != nil
}

// List returns the current generation together with managed and
// configuration-provided users (without any credentials).
func (u *Users) List() APIUsersView {
	snap := u.current.Load()
	view := APIUsersView{}
	if snap == nil {
		return view
	}
	view.Generation = snap.generation
	configNames := make([]string, 0, len(snap.configNames))
	for name := range snap.configNames {
		configNames = append(configNames, name)
	}
	slices.Sort(configNames)
	for _, mu := range snap.managed {
		view.Users = append(view.Users, APIUserView{Username: mu.Name, Source: "managed"})
	}
	for _, name := range configNames {
		if managedUserByName(snap.managed, name) == nil {
			view.Users = append(view.Users, APIUserView{Username: name, Source: "config"})
		}
	}
	view.LastFailure = u.lastFailure.Load()
	return view
}

// Get returns one user by name (managed users first).
func (u *Users) Get(username string) (APIUserView, bool) {
	snap := u.current.Load()
	if snap == nil {
		return APIUserView{}, false
	}
	if managedUserByName(snap.managed, username) != nil {
		return APIUserView{Username: username, Source: "managed"}, true
	}
	if _, ok := snap.configNames[username]; ok {
		return APIUserView{Username: username, Source: "config"}, true
	}
	return APIUserView{}, false
}

// Commit applies one add/delete/rotate operation under the single
// persist-then-publish rule shared by all three change kinds.
func (u *Users) Commit(in APIUserCommitInput) (APIUserCommitResult, error) {
	if !u.Enabled() {
		return APIUserCommitResult{}, ErrAPIUsersDisabled
	}

	u.commitMu.Lock()
	defer u.commitMu.Unlock()

	data := u.storage.Current()
	snap := u.current.Load()

	// Idempotent replay: never apply the same persisted operation twice.
	if entry := data.FindOperation(in.OperationID); entry != nil {
		return u.replay(in, entry, data, snap)
	}

	// Optimistic generation check: an operation based on an older generation
	// can never undo a newer successful result.
	if in.BaseGeneration != data.Generation {
		return APIUserCommitResult{}, fmt.Errorf("%w: current generation is %d, request is based on %d",
			ErrStaleGeneration, data.Generation, in.BaseGeneration)
	}

	if err := validateChange(in, data, snap); err != nil {
		return APIUserCommitResult{}, err
	}

	// Hash before touching durable state; from here on the plaintext password
	// is no longer referenced and only the hash enters the document/journal.
	passwordHash := ""
	if in.Kind == APIUserAdd || in.Kind == APIUserRotate {
		h, err := hashPassword(in.Password)
		if err != nil {
			return APIUserCommitResult{}, err
		}
		passwordHash = h
	}

	nextGeneration := data.Generation + 1
	entry := storagetype.JournalEntry{
		ID:               in.OperationID,
		Kind:             storagetype.OperationKind(in.Kind),
		Username:         in.Username,
		BaseGeneration:   data.Generation,
		ResultGeneration: nextGeneration,
		Status:           storagetype.StatusPersisted,
		Timestamp:        u.now(),
	}
	if passwordHash != "" {
		entry.PasswordHash = passwordHash
	}

	next := data
	next.Users = applyChange(data.Users, in, passwordHash)
	next.Generation = nextGeneration
	next.Journal = storagetype.AppendJournal(data.Journal, entry)
	// Fold a pending diagnostic from an earlier failed write into the next
	// durable document.
	if pending := u.lastFailure.Load(); pending != nil {
		next.LastFailure = failureRecordFromView(pending)
	}

	if err := u.storage.Commit(next); err != nil {
		// Durable state and the active snapshot are untouched; the old
		// credentials stay valid and the same operation may be retried.
		view := u.failureView(in.OperationID, storagetype.PhasePersist, data.Generation, err)
		u.lastFailure.Store(&view)
		log.Warningf("API user change not persisted: operation_id=%q kind=%s username=%q base_generation=%d: %v",
			in.OperationID, in.Kind, in.Username, in.BaseGeneration, err)
		return APIUserCommitResult{}, err
	}

	// Durable from here on. The hook models the crash window between the
	// durable write and snapshot publication.
	if u.hooks.afterDurablePersist != nil {
		if err := u.hooks.afterDurablePersist(next); err != nil {
			view := u.failureView(in.OperationID, storagetype.PhasePublish, nextGeneration, err)
			u.lastFailure.Store(&view)
			log.Warningf("API user change persisted but snapshot not published: operation_id=%q generation=%d: %v",
				in.OperationID, nextGeneration, err)
			return APIUserCommitResult{}, &PublishError{OperationID: in.OperationID, Err: err}
		}
	}

	u.publish(nextGeneration, next.Users, snap)
	u.lastFailure.Store(nil)
	u.markJournalPublished(next)

	return APIUserCommitResult{
		OperationID: in.OperationID,
		Kind:        in.Kind,
		Username:    in.Username,
		Generation:  nextGeneration,
		Status:      StatusCommitted,
	}, nil
}

// replay returns the original result of a persisted operation without
// applying it again. When the active snapshot lags the durable generation
// (unpublished generation, including after the publication window), it is
// repaired from durable state.
func (u *Users) replay(in APIUserCommitInput, entry *storagetype.JournalEntry, data storagetype.ClusterModeData, snap *authSnapshot) (APIUserCommitResult, error) {
	if in.Kind != APIUserKind(entry.Kind) || in.Username != entry.Username {
		return APIUserCommitResult{}, fmt.Errorf("%w: operation %q was recorded as %s on %q",
			ErrOperationIDConflict, in.OperationID, entry.Kind, entry.Username)
	}
	if entry.Kind == storagetype.OpAdd || entry.Kind == storagetype.OpRotate {
		if err := crypt.SHA512.New().Verify(entry.PasswordHash, []byte(in.Password)); err != nil {
			return APIUserCommitResult{}, fmt.Errorf("%w: operation %q recorded a different password",
				ErrOperationIDConflict, in.OperationID)
		}
	}

	lagging := snap == nil || snap.generation < data.Generation || entry.Status == storagetype.StatusPersisted
	if lagging {
		// Complete the unpublished generation(s) by rebuilding from the
		// durable version; no password is re-hashed and no change replayed.
		u.publish(data.Generation, data.Users, snap)
		u.markJournalPublished(data)
	}

	return APIUserCommitResult{
		OperationID: in.OperationID,
		Kind:        in.Kind,
		Username:    in.Username,
		Generation:  entry.ResultGeneration,
		Status:      StatusReplayed,
	}, nil
}

func validateChange(in APIUserCommitInput, data storagetype.ClusterModeData, snap *authSnapshot) error {
	_, isConfigUser := snap.configNames[in.Username]
	switch in.Kind {
	case APIUserAdd:
		if managedUserByName(data.Users, in.Username) != nil {
			return fmt.Errorf("%w: %q", ErrUserAlreadyExists, in.Username)
		}
		if isConfigUser {
			return fmt.Errorf("%w: %q", ErrConfigUserCollision, in.Username)
		}
	case APIUserDelete, APIUserRotate:
		if isConfigUser {
			return fmt.Errorf("%w: %q", ErrCannotManageConfigUser, in.Username)
		}
		if managedUserByName(data.Users, in.Username) == nil {
			return fmt.Errorf("%w: %q", ErrManagedUserNotFound, in.Username)
		}
	default:
		return fmt.Errorf("unknown API user operation kind %q", in.Kind)
	}
	return nil
}

// applyChange computes the next managed user set from a copy; the input slice
// is never modified in place.
func applyChange(users storagetype.Users, in APIUserCommitInput, passwordHash string) storagetype.Users {
	next := make(storagetype.Users, len(users))
	copy(next, users)
	switch in.Kind {
	case APIUserAdd:
		hash := passwordHash
		next = append(next, storagetype.User{Name: in.Username, Password: &hash})
	case APIUserDelete:
		for i, candidate := range next {
			if candidate.Name == in.Username {
				next = slices.Delete(next, i, i+1)
				break
			}
		}
	case APIUserRotate:
		for i := range next {
			if next[i].Name == in.Username {
				hash := passwordHash
				next[i].Password = &hash
				// A rotated API user is always a securely hashed user.
				next[i].Insecure = nil
				break
			}
		}
	}
	return next
}

// markJournalPublished best-effort rewrites the durable document with every
// journal entry in "published" state. A failure only means the entry stays
// "persisted" until the next replay repair or the next startup reconcile; it
// must not fail the operation, which is already durable and published.
func (u *Users) markJournalPublished(doc storagetype.ClusterModeData) {
	published := doc
	changed := false
	if doc.LastFailure == nil {
		if pending := u.lastFailure.Load(); pending != nil {
			published.LastFailure = failureRecordFromView(pending)
		}
	}
	published.Journal = make(storagetype.Journal, len(doc.Journal))
	copy(published.Journal, doc.Journal)
	for i := range published.Journal {
		if published.Journal[i].Status != storagetype.StatusPublished {
			published.Journal[i].Status = storagetype.StatusPublished
			changed = true
		}
	}
	if published.LastFailure != nil {
		changed = true
	}
	if !changed {
		return
	}
	if err := u.storage.Commit(published); err != nil {
		log.Warningf("API user journal status remains unpublished until repair or restart: generation=%d: %v",
			published.Generation, err)
		if published.LastFailure != nil {
			view := failureViewFromRecord(published.LastFailure)
			u.lastFailure.Store(&view)
		}
		return
	}
	u.lastFailure.Store(nil)
}

func hashPassword(plaintext string) (string, error) {
	hashed, err := crypt.SHA512.New().Generate([]byte(plaintext), nil)
	if err != nil {
		return "", fmt.Errorf("failed to hash API user password: %w", err)
	}
	return hashed, nil
}

func (u *Users) failureView(operationID string, phase storagetype.FailurePhase, generation uint64, cause error) APIUserFailureView {
	return APIUserFailureView{
		OperationID: operationID,
		Phase:       phase,
		Message:     cause.Error(),
		Generation:  generation,
		Timestamp:   u.now(),
	}
}

func failureViewFromRecord(r *storagetype.FailureRecord) APIUserFailureView {
	return APIUserFailureView{
		OperationID: r.OperationID,
		Phase:       r.Phase,
		Message:     r.Message,
		Generation:  r.Generation,
		Timestamp:   r.Timestamp,
	}
}

func failureRecordFromView(v *APIUserFailureView) *storagetype.FailureRecord {
	return &storagetype.FailureRecord{
		OperationID: v.OperationID,
		Phase:       v.Phase,
		Message:     v.Message,
		Generation:  v.Generation,
		Timestamp:   v.Timestamp,
	}
}
