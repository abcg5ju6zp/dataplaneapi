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

package storage

import (
	"errors"
	"time"
)

// State is the recovery conclusion a state store reached at its last
// open/recovery or write transaction. Each kind of internal state
// (users, Consul definitions, AWS regions) reaches its own conclusion
// independently.
type State int

const (
	// Healthy means the active generation was read and verified; writes
	// are allowed. A missing or legacy-format file on first start is also
	// Healthy.
	Healthy State = iota
	// Recovered means the active file was unusable but the last known
	// good generation was restored; writes are allowed.
	Recovered
	// ReadOnlyIsolated means a verified last known good generation is
	// served from memory, but it could not be written back to the active
	// file; writes are rejected, reads keep working.
	ReadOnlyIsolated
	// Unavailable means neither the active file nor the last known good
	// copy could be verified; no data is available and all writes are
	// rejected. Only the subsystem depending on this state is isolated;
	// unrelated subsystems keep running.
	Unavailable
)

func (s State) String() string {
	switch s {
	case Healthy:
		return "healthy"
	case Recovered:
		return "recovered"
	case ReadOnlyIsolated:
		return "read-only isolated"
	case Unavailable:
		return "unavailable"
	default:
		return "unknown"
	}
}

// Writable reports whether a new generation may be committed in this state.
func (s State) Writable() bool {
	return s == Healthy || s == Recovered
}

var (
	// ErrWritePending is returned when a write failed before the active
	// file was replaced (marshalling, temp file or backup failure). The
	// active generation is untouched and the same write may be retried.
	ErrWritePending = errors.New("storage: write failed before being committed; the previous generation is intact, retry the write")
	// ErrGenerationVerifyFailed is returned when, after the atomic
	// replacement, the new generation could not be verified by re-reading
	// the active file; the store fell back to the last known good
	// generation.
	ErrGenerationVerifyFailed = errors.New("storage: new generation failed verification after commit; reverted to the last known good generation")
	// ErrReadOnly is returned when the store is serving the last known
	// good generation but cannot persist a new one (recovery write-back
	// failed). The store remains read-only until the next successful
	// recovery.
	ErrReadOnly = errors.New("storage: state file is read-only isolated; serving the last known good generation, writes are rejected")
	// ErrStorageUnavailable is returned when neither the active file nor
	// the last known good copy is usable. The dependent subsystem must
	// report itself unavailable instead of taking the process down.
	ErrStorageUnavailable = errors.New("storage: state file and the last known good copy are unusable; subsystem is isolated")
	// ErrStaleGeneration is returned when the on-disk generation is newer
	// than the generation the caller based its write on (a concurrent
	// process or request committed first). The old generation must never
	// overwrite the newer one; the caller should reload and retry.
	ErrStaleGeneration = errors.New("storage: refusing to overwrite a newer on-disk generation; reload the state and retry")
)

// Subsystem names used in status reports and log messages.
const (
	SubsystemUsers = "users"
	SubsystemConsul = "consul"
	SubsystemAWS    = "aws_regions"
)

// StatusReport is the independent recovery conclusion for one state file.
// It never contains state contents, secrets or raw file bytes.
type StatusReport struct {
	// Name is the subsystem identifier (users, consul, aws_regions).
	Name string `json:"name"`
	// File is the absolute active file path.
	File string `json:"file"`
	// State is the final conclusion.
	State State `json:"state"`
	// ActiveGeneration is the generation currently served.
	ActiveGeneration uint64 `json:"active_generation"`
	// LKGGeneration is the generation of the on-disk last known good copy
	// (0 when absent).
	LKGGeneration uint64 `json:"lkg_generation"`
	// Since is when the current state was entered.
	Since time.Time `json:"since"`
	// Detail is a human readable, secret-free explanation.
	Detail string `json:"detail,omitempty"`
}
