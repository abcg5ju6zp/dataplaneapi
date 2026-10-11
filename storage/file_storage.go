package storage

import (
	"path/filepath"
)

// fileStorage is the thin adapter over the durable, generational engine.
// The filePath-only struct literal is kept compatible with existing
// callers/tests; the engine itself is registered once per absolute path
// and shared by every adapter pointing at it.
type fileStorage[T Storable] struct {
	filePath string
}

// newFileStorage builds a fileStorage for the given path.
func newFileStorage[T Storable](filePath string) *fileStorage[T] {
	return &fileStorage[T]{filePath: filePath}
}

// subsystemNameFor derives the stable subsystem identifier from the
// well-known state file basename. Unknown names fall back to the basename
// itself.
func subsystemNameFor(filePath string) string {
	switch filepath.Base(filePath) {
	case ClusterModeDataFileName:
		return SubsystemUsers
	case filepath.Base(ConsulFileName):
		return SubsystemConsul
	case filepath.Base(AWSRegionFileName):
		return SubsystemAWS
	default:
		return filepath.Base(filePath)
	}
}

func (f *fileStorage[T]) durable() *durableEngine[T] {
	return getOrCreateEngine[T](f.filePath, subsystemNameFor(f.filePath))
}

func (f *fileStorage[T]) Get() (T, error) {
	return f.durable().Reload()
}

func (f *fileStorage[T]) Store(data T) error {
	return f.durable().Store(data)
}

func (f *fileStorage[T]) Active() T {
	return f.durable().Active()
}

func (f *fileStorage[T]) Status() StatusReport {
	return f.durable().Status()
}

// initFile keeps the historical name used by the subsystem wrappers:
// opening a store runs startup recovery and never fatals on a
// non-writable directory (the conclusion is reported through Status).
func (f *fileStorage[T]) initFile() error {
	f.durable()
	return nil
}
