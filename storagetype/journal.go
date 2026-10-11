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

package storagetype

import "time"

// JournalLimit bounds the persisted operation journal to the most recent
// operations. Idempotent deduplication only covers operations within the
// window; older retries are rejected as new operations (stale generation or
// duplicate username) and never mutate state twice.
const JournalLimit = 100

// OperationKind identifies the kind of an API user change.
type OperationKind string

const (
	OpAdd    OperationKind = "add"
	OpDelete OperationKind = "delete"
	OpRotate OperationKind = "rotate_password"
)

// Journal entry statuses.
const (
	StatusPersisted = "persisted"
	StatusPublished = "published"
)

// JournalEntry records one durable API user change for idempotent retries.
// PasswordHash is only present for add/rotate and is always a crypt hash
// (never a plaintext password).
type JournalEntry struct {
	ID               string        `json:"id"`
	Kind             OperationKind `json:"kind"`
	Username         string        `json:"username"`
	PasswordHash     string        `json:"password_hash,omitempty"`
	BaseGeneration   uint64        `json:"base_generation"`
	ResultGeneration uint64        `json:"result_generation"`
	Status           string        `json:"status"`
	Timestamp        time.Time     `json:"timestamp"`
}

// Journal is the bounded list of recent user-change operations, newest last.
type Journal []JournalEntry

// AppendJournal appends entry, keeping at most JournalLimit recent entries.
func AppendJournal(j Journal, entry JournalEntry) Journal {
	if len(j) >= JournalLimit {
		j = j[len(j)-JournalLimit+1:]
	}
	return append(j, entry)
}

// FindOperation returns the most recent journal entry with the given operation
// id, or nil when it is not in the retained window.
func (d ClusterModeData) FindOperation(id string) *JournalEntry {
	for i := len(d.Journal) - 1; i >= 0; i-- {
		if d.Journal[i].ID == id {
			return &d.Journal[i]
		}
	}
	return nil
}

// FailurePhase pinpoints which phase of a user change failed, so callers can
// distinguish a durable-write failure (retry the operation) from an
// unpublished durable generation (repair/restart recovery).
type FailurePhase string

const (
	PhasePersist   FailurePhase = "persist"
	PhasePublish   FailurePhase = "publish"
	PhaseReconcile FailurePhase = "reconcile"
)

// FailureRecord is the most recent diagnosable failure. Messages must never
// contain passwords or password hashes.
type FailureRecord struct {
	OperationID string       `json:"operation_id"`
	Phase       FailurePhase `json:"phase"`
	Message     string       `json:"message"`
	Generation  uint64       `json:"generation"`
	Timestamp   time.Time    `json:"timestamp"`
}
