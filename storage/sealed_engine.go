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
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/google/renameio"
	native_misc "github.com/haproxytech/client-native/v6/misc"
)

const (
	lkgSuffix       = ".lkg"
	lockSuffix      = ".lock"
	flockWait       = 5 * time.Second
	flockRetryEvery = 50 * time.Millisecond
)

// fsyncError unwraps nothing special; kept for clarity at call sites.
var (
	errFlockBusy = errors.New("storage: state file is locked by another process")
	// errInvalidJSON replaces parser error strings: JSON libraries quote
	// snippets of the input in their errors, which could leak credentials
	// from corrupt state files into diagnostics or log messages.
	errInvalidJSON = errors.New("state content is not valid JSON")
)

// fileObservation is the parsed and verified view of one on-disk file
// (active or last known good).
type fileObservation[T any] struct {
	exists bool
	empty  bool
	raw    []byte
	dec    decodedGeneration[T]
	// err is the parse/verification failure; nil when the content is
	// absent, empty or verified.
	err error
}

func (o fileObservation[T]) usable() bool {
	return o.exists && !o.empty && o.err == nil
}

func observeFile[T any](path string) fileObservation[T] {
	o := fileObservation[T]{}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return o
		}
		o.exists = true
		o.err = err
		return o
	}
	o.exists = true
	o.raw = raw
	if len(raw) == 0 {
		o.empty = true
		return o
	}
	dec, err := decodeGeneration[T](raw)
	if err != nil {
		// Never propagate the parser's own error string: it may quote
		// input snippets containing credentials.
		o.err = errInvalidJSON
		return o
	}
	o.dec = dec
	if err := dec.verify(raw); err != nil {
		o.err = err
	}
	return o
}

// durableEngine is the generational, integrity-checked, recoverable
// storage for one state file. It is shared per absolute path inside the
// process and coordinates with other processes through flock.
type durableEngine[T Storable] struct {
	name     string
	path     string
	lkgPath  string
	lockPath string

	mu        sync.RWMutex
	active    T
	activeGen uint64
	lkgGen    uint64
	state     State
	since     time.Time
	detail    string
	// opened is false until the first open/recovery ran. It lets a
	// verified active file on first open conclude Healthy even though the
	// struct starts in Unavailable.
	opened bool

	// Test-only fault injection points; nil in production.
	hookBeforeCommit  func() error
	hookAfterCommit   func() error
	hookBeforeRestore func() error
}

// engineRegistry guarantees one engine (and one in-process transaction
// mutex) per absolute state file path.
var engineRegistry sync.Map // abs path -> *durableEngine[T]

func getOrCreateEngine[T Storable](path, name string) *durableEngine[T] {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	if e, ok := engineRegistry.Load(abs); ok {
		return e.(*durableEngine[T])
	}
	e := &durableEngine[T]{
		name:     name,
		path:     abs,
		lkgPath:  abs + lkgSuffix,
		lockPath: abs + lockSuffix,
		state:    Unavailable,
		since:    time.Now().UTC(),
	}
	actual, loaded := engineRegistry.LoadOrStore(abs, e)
	eng := actual.(*durableEngine[T])
	if !loaded {
		eng.open()
	}
	return eng
}

func (e *durableEngine[T]) set(state State, detail string) {
	e.state = state
	e.detail = detail
	e.since = time.Now().UTC()
}

// open creates the storage directory and runs the startup recovery.
// It never fatals: environment failures become the Unavailable state so
// the dependent subsystem can be isolated while the process keeps
// running.
func (e *durableEngine[T]) open() {
	dir := filepath.Dir(e.path)
	if _, err := native_misc.CheckOrCreateWritableDirectory(dir); err != nil {
		e.set(Unavailable, fmt.Sprintf("cannot prepare storage directory %s: %v", dir, err))
		return
	}
	lock, err := acquireFlock(e.lockPath, true)
	if err != nil {
		e.set(Unavailable, fmt.Sprintf("cannot lock state file: %v", err))
		return
	}
	defer lock.release()

	sweepStaleTempFiles(e.path)
	e.recoverLocked(stageStartup)
}

// Reload re-runs the recovery protocol and returns the generation now in
// force (used by Load()).
func (e *durableEngine[T]) Reload() (T, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Recovery is re-run unconditionally: an operator may have repaired
	// the disk after an Unavailable/ReadOnly conclusion.
	lock, err := acquireFlock(e.lockPath, true)
	if err != nil {
		return e.active, nil // keep serving the in-memory generation
	}
	defer lock.release()
	sweepStaleTempFiles(e.path)
	e.recoverLocked(stageStartup)
	return e.active, nil
}

func (e *durableEngine[T]) Active() T {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.active
}

func (e *durableEngine[T]) Status() StatusReport {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return StatusReport{
		Name:             e.name,
		File:             e.path,
		State:            e.state,
		ActiveGeneration: e.activeGen,
		LKGGeneration:    e.lkgGen,
		Since:            e.since,
		Detail:           e.detail,
	}
}

// recoverLocked decides the recovery conclusion by comparing the active
// file and the last known good copy. The caller must hold the exclusive
// flock.
func (e *durableEngine[T]) recoverLocked(stage quarantineStage) {
	main := observeFile[T](e.path)
	lkg := observeFile[T](e.lkgPath)
	e.lkgGen = 0
	firstOpen := !e.opened
	e.opened = true

	switch {
	case main.usable():
		e.active = main.dec.data
		e.activeGen = main.dec.generation
		// Crash between candidate flush and watermark confirmation:
		// an intact newer active generation is confirmed here; make
		// sure the LKG copy tracks the previous generation.
		if !lkg.usable() || lkg.dec.generation < main.dec.generation {
			if err := atomicWrite(e.lkgPath, main.raw); err != nil {
				e.set(Healthy, fmt.Sprintf("active generation %d verified; last known good copy could not be refreshed: %v", main.dec.generation, err))
				break
			}
		}
		e.lkgGen = main.dec.generation
		switch {
		case firstOpen, e.state == Healthy:
			e.set(Healthy, "")
		case e.state == Recovered:
			// Keep reporting the recovery conclusion for the process
			// lifetime; a verified write clears it.
		default:
			// Unavailable/ReadOnly with an intact active file means the
			// underlying problem was repaired on disk.
			e.set(Recovered, fmt.Sprintf("state recovered: active generation %d verified", main.dec.generation))
		}
	case lkg.usable():
		// Active file is absent, truncated or corrupt; keep a safe
		// diagnostic of non-empty corrupt samples, then restore.
		if main.exists && !main.empty {
			_ = writeQuarantineRecord(e.path, stage, main.raw, main.err, main.dec.generation, lkg.dec.generation)
		} else if main.empty {
			_ = writeQuarantineRecord(e.path, stage, nil, errors.New("active state file is empty (truncated)"), 0, lkg.dec.generation)
		}
		if err := atomicWrite(e.path, lkg.raw); err != nil {
			e.active = lkg.dec.data
			e.activeGen = lkg.dec.generation
			e.lkgGen = lkg.dec.generation
			e.set(ReadOnlyIsolated, fmt.Sprintf("restored generation %d in memory but could not write it back to %s: %v", lkg.dec.generation, e.path, err))
			return
		}
		check := observeFile[T](e.path)
		if !check.usable() {
			e.active = lkg.dec.data
			e.activeGen = lkg.dec.generation
			e.lkgGen = lkg.dec.generation
			e.set(ReadOnlyIsolated, fmt.Sprintf("restored copy of generation %d failed verification after write-back", lkg.dec.generation))
			return
		}
		e.active = lkg.dec.data
		e.activeGen = lkg.dec.generation
		e.lkgGen = lkg.dec.generation
		e.set(Recovered, fmt.Sprintf("active state file %s was unusable; restored last known good generation %d", filepath.Base(e.path), lkg.dec.generation))
	default:
		// Neither copy is usable. Non-empty unreadable content is
		// evidence of corruption: preserve it and isolate only this
		// subsystem, never overwrite with an empty object.
		corruptEvidence := false
		if main.exists && !main.empty {
			_ = writeQuarantineRecord(e.path, stage, main.raw, main.err, main.dec.generation, 0)
			corruptEvidence = true
		}
		if lkg.exists && !lkg.empty {
			_ = writeQuarantineRecord(e.lkgPath, stage, lkg.raw, lkg.err, 0, lkg.dec.generation)
			corruptEvidence = true
		}
		var zero T
		e.active = zero
		e.activeGen = 0
		if corruptEvidence {
			detail := fmt.Sprintf("active state file %s and last known good copy are unusable", filepath.Base(e.path))
			if main.exists && main.err != nil {
				detail = fmt.Sprintf("%s: %v", detail, main.err)
			}
			e.set(Unavailable, detail)
		} else {
			// First boot (no file) or a legacy 0-byte initialized file.
			e.set(Healthy, "")
		}
	}
}

// Store commits a new generation. The complete candidate is formed and
// written first, atomically replaces the active file, and the in-memory
// active object advances only after the replaced file is re-read and
// verified.
func (e *durableEngine[T]) Store(data T) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	switch e.state {
	case Unavailable:
		return ErrStorageUnavailable
	case ReadOnlyIsolated:
		return ErrReadOnly
	}

	lock, err := acquireFlock(e.lockPath, true)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWritePending, err)
	}
	defer lock.release()

	main := observeFile[T](e.path)
	lkg := observeFile[T](e.lkgPath)

	firstWrite := (!main.exists || main.empty) && !lkg.usable() && e.state == Healthy && e.activeGen == 0
	if !main.usable() && !firstWrite {
		// The active file became unusable underneath us (external
		// truncation, or a copy to fall back on): run the same recovery
		// as startup before doing anything.
		e.recoverLocked(stageCommitVerify)
		switch e.state {
		case Unavailable:
			return ErrStorageUnavailable
		case ReadOnlyIsolated:
			return ErrReadOnly
		default:
			return ErrGenerationVerifyFailed
		}
	}

	diskGen := main.dec.generation
	if diskGen > e.activeGen {
		// Another process/engine committed a newer generation. Refresh
		// the active view and refuse to let the old generation win.
		e.active = main.dec.data
		e.activeGen = diskGen
		return ErrStaleGeneration
	}

	// Backup phase: the verified active generation becomes the last
	// known good copy before it is replaced. Any failure here happens
	// before the active file is touched and the same write may be
	// retried.
	if main.usable() {
		if err := e.refreshLKG(main, lkg); err != nil {
			return err
		}
	}

	if e.hookBeforeCommit != nil {
		if err := e.hookBeforeCommit(); err != nil {
			return fmt.Errorf("%w: %v", ErrWritePending, err)
		}
	}

	candidate, err := encodeGeneration(data, diskGen+1)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWritePending, err)
	}
	if err := atomicWrite(e.path, candidate); err != nil {
		return fmt.Errorf("%w: %v", ErrWritePending, err)
	}

	if e.hookAfterCommit != nil {
		_ = e.hookAfterCommit()
	}

	// Re-read from disk and verify before advancing the watermark.
	committed := observeFile[T](e.path)
	if committed.usable() && committed.dec.generation == diskGen+1 {
		e.active = data
		e.activeGen = diskGen + 1
		e.lkgGen = diskGen
		e.set(Healthy, "")
		return nil
	}

	// Verification failed after atomic replacement. Preserve a safe
	// diagnostic and fall back to the last known good generation.
	cause := committed.err
	if cause == nil {
		cause = errors.New("committed generation failed verification")
	}
	_ = writeQuarantineRecord(e.path, stageCommitVerify, committed.raw, cause, diskGen+1, diskGen)

	if e.hookBeforeRestore != nil {
		if err := e.hookBeforeRestore(); err != nil {
			e.markReadOnly(main, lkg, err)
			return ErrReadOnly
		}
	}
	restore := observeFile[T](e.lkgPath)
	if !restore.usable() || atomicWrite(e.path, restore.raw) != nil {
		e.markReadOnly(main, restore, errors.New("last known good copy could not be written back"))
		return ErrReadOnly
	}
	check := observeFile[T](e.path)
	if !check.usable() {
		e.markReadOnly(main, restore, errors.New("restored copy failed verification"))
		return ErrReadOnly
	}
	e.active = restore.dec.data
	e.activeGen = restore.dec.generation
	e.lkgGen = restore.dec.generation
	e.set(Recovered, fmt.Sprintf("generation %d failed verification; reverted to last known good generation %d", diskGen+1, restore.dec.generation))
	return ErrGenerationVerifyFailed
}

// markReadOnly enters the read-only isolated state. The last known good
// generation is kept in memory so reads continue to work; writes are
// rejected until a later recovery succeeds.
func (e *durableEngine[T]) markReadOnly(main, lkg fileObservation[T], cause error) {
	if lkg.usable() {
		e.active = lkg.dec.data
		e.activeGen = lkg.dec.generation
		e.lkgGen = lkg.dec.generation
	} else if main.usable() {
		e.active = main.dec.data
		e.activeGen = main.dec.generation
	}
	e.set(ReadOnlyIsolated, fmt.Sprintf("serving last known good generation in memory, persistence unavailable: %v", cause))
}

// refreshLKG makes the LKG copy hold the verified active generation.
// Failure returns ErrWritePending because the active file has not been
// touched yet.
func (e *durableEngine[T]) refreshLKG(main, lkg fileObservation[T]) error {
	if lkg.usable() && lkg.dec.generation >= main.dec.generation && lkg.exists {
		e.lkgGen = lkg.dec.generation
		return nil
	}
	if lkg.exists && !lkg.empty && !lkg.usable() {
		// A corrupt LKG is evidence: quarantine it before replacing.
		_ = writeQuarantineRecord(e.lkgPath, stageCommitVerify, lkg.raw, lkg.err, lkg.dec.generation, main.dec.generation)
	}
	if err := atomicWrite(e.lkgPath, main.raw); err != nil {
		return fmt.Errorf("%w: could not refresh last known good copy: %v", ErrWritePending, err)
	}
	e.lkgGen = main.dec.generation
	return nil
}

// ---- file system primitives ----

func mkdirPrivate(dir string) error {
	return os.MkdirAll(dir, 0o700)
}

func writeFilePrivate(path string, data []byte) error {
	return renameio.WriteFile(path, data, 0o600)
}

// atomicWrite writes data to a temp file in the destination directory,
// fsyncs it, renames it over path and fsyncs the directory so the rename
// is durable (renameio itself does not fsync the directory).
func atomicWrite(path string, data []byte) error {
	if err := writeFilePrivate(path, data); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// sweepStaleTempFiles removes renameio leftovers (".<base><random>")
// from a crash between temp creation and rename. Must be called while
// holding the exclusive flock.
func sweepStaleTempFiles(path string) {
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	prefix := "." + filepath.Base(path)
	for _, en := range entries {
		if en.IsDir() {
			continue
		}
		name := en.Name()
		if len(name) > len(prefix) && name[:len(prefix)] == prefix {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}

// ---- flock ----

type flockHandle struct {
	file *os.File
}

func acquireFlock(lockPath string, exclusive bool) (*flockHandle, error) {
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	how := syscall.LOCK_SH | syscall.LOCK_NB
	if exclusive {
		how = syscall.LOCK_EX | syscall.LOCK_NB
	}
	deadline := time.Now().Add(flockWait)
	for {
		err := syscall.Flock(int(f.Fd()), how)
		if err == nil {
			return &flockHandle{file: f}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, errFlockBusy
		}
		time.Sleep(flockRetryEvery)
	}
}

func (h *flockHandle) release() {
	_ = syscall.Flock(int(h.file.Fd()), syscall.LOCK_UN)
	_ = h.file.Close()
}
