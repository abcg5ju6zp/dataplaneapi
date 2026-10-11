package storage

import (
	"github.com/haproxytech/dataplaneapi/storagetype"
)

// type constraint for storable objects, add more when need arises with |
type Storable interface {
	storagetype.ClusterModeData | storagetype.ConsulData | storagetype.AWSRegionData
}

// Storage persists one kind of internal dataplane state.
//
// Implementations guarantee:
//   - monotonic generations and content integrity checks on disk;
//   - a last known good copy kept next to the active file;
//   - atomic replacement, re-read verification before advancing the
//     in-memory active generation;
//   - independent recovery conclusions (see Status), never a fatal exit.
type Storage[T Storable] interface {
	// Get (re)runs recovery from the active file and returns the
	// generation currently in force. It does not return an error for a
	// corrupt state: inspect Status to learn the conclusion.
	Get() (T, error)
	// Store commits a new generation or returns a sentinel error
	// describing why it could not (see ErrWritePending,
	// ErrGenerationVerifyFailed, ErrReadOnly, ErrStorageUnavailable,
	// ErrStaleGeneration).
	Store(data T) error
	// Active returns the in-memory active generation without touching
	// disk.
	Active() T
	// Status returns the independent recovery conclusion for this state.
	Status() StatusReport
}
