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
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/google/renameio"
	native_misc "github.com/haproxytech/client-native/v6/misc"
	"golang.org/x/sys/unix"
)

// rejectedRecord describes a candidate that was structurally valid but
// failed the dependency precheck and was rolled back.
type rejectedRecord struct {
	Generation uint64    `json:"generation"`
	At         time.Time `json:"at"`
	File       string    `json:"file"`
	Reason     string    `json:"reason"`
}

// hotReloadState is the persisted ledger of the last accepted generation.
// It is the only on-disk authority that survives a crash mid-validation or
// mid-switch; content that never passed all gates is never recorded here.
type hotReloadState struct {
	Version      int             `json:"version"`
	Generation   uint64          `json:"generation"`
	Fingerprint  string          `json:"fingerprint"`
	ConfigPath   string          `json:"config_path"`
	AcceptedAt   time.Time       `json:"accepted_at"`
	LastRejected *rejectedRecord `json:"last_rejected,omitempty"`
}

// stateStore owns the ledger directory next to the config file:
//
//	.<config-file>.hotreload/
//	├── state.json                 accepted generation ledger (atomic, 0600)
//	├── last-active.yaml           exact bytes of the last accepted candidate
//	├── rejected-<generation>.yaml candidates rolled back after dep failure (newest 5)
//	├── .lock                      inter-process transaction lock
//	└── .<name>*                   renameio leftovers, swept at startup
//
// The directory sits beside the config file rather than under the configured
// storage directory because it must remain locatable when the config content
// itself is corrupt (the storage directory is configured inside that YAML).
// The non-recursive file watcher ignores it by exact-name filtering.
type stateStore struct {
	dir        string
	configPath string
}

func newStateStore(configPath string) *stateStore {
	clean := filepath.Clean(configPath)
	return &stateStore{
		dir:        filepath.Join(filepath.Dir(clean), fmt.Sprintf(hotReloadDirNamePattern, filepath.Base(clean))),
		configPath: clean,
	}
}

func (s *stateStore) statePath() string  { return filepath.Join(s.dir, stateFileName) }
func (s *stateStore) backupPath() string { return filepath.Join(s.dir, backupFileName) }
func (s *stateStore) lockPath() string   { return filepath.Join(s.dir, lockFileName) }

func (s *stateStore) rejectedPath(generation uint64) string {
	return filepath.Join(s.dir, fmt.Sprintf("%s%d%s", rejectedFilePrefix, generation, rejectedFileSuffix))
}

// ensureDir creates the state directory; it is the only MkdirAll site.
func (s *stateStore) ensureDir() error {
	if _, err := native_misc.CheckOrCreateWritableDirectory(s.dir); err != nil {
		return fmt.Errorf("hot-reload state directory %s is not writable: %w", s.dir, err)
	}
	return nil
}

func (s *stateStore) exists() bool {
	_, err := os.Stat(s.statePath())
	return err == nil
}

// load reads and validates the ledger. A corrupt ledger or an unsupported
// schema version is a hard error: booting unvalidated content on top of an
// untrusted ledger is never acceptable. A ledger recorded for a different
// configuration path is reported as foreign instead.
func (s *stateStore) load() (*hotReloadState, bool, error) {
	data, err := os.ReadFile(s.statePath())
	if err != nil {
		return nil, false, err
	}
	st := &hotReloadState{}
	if err := json.Unmarshal(data, st); err != nil {
		return nil, false, fmt.Errorf("hot-reload state file %s is corrupt: %w; inspect %s and remove it only after verifying the active configuration", s.statePath(), err, s.dir)
	}
	if st.Version != hotReloadStateVer || st.Fingerprint == "" || st.Generation == 0 {
		return nil, false, fmt.Errorf("hot-reload state file %s uses an unsupported schema: inspect %s manually", s.statePath(), s.dir)
	}
	if filepath.Clean(st.ConfigPath) != s.configPath {
		return st, true, nil
	}
	return st, false, nil
}

func (s *stateStore) commit(st hotReloadState) error {
	st.Version = hotReloadStateVer
	st.ConfigPath = s.configPath
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return renameio.WriteFile(s.statePath(), data, hotReloadFileMode)
}

func (s *stateStore) writeBackup(raw []byte) error {
	return renameio.WriteFile(s.backupPath(), raw, hotReloadFileMode)
}

func (s *stateStore) backupExists() bool {
	_, err := os.Stat(s.backupPath())
	return err == nil
}

func (s *stateStore) readBackup() ([]byte, error) {
	return os.ReadFile(s.backupPath())
}

// restoreBackupTo atomically replaces the configuration file with the last
// accepted content, with the same 0600 mode cfg.Save() uses.
func (s *stateStore) restoreBackupTo(configPath string) error {
	raw, err := s.readBackup()
	if err != nil {
		return err
	}
	return renameio.WriteFile(configPath, raw, hotReloadFileMode)
}

// saveRejected preserves a rolled-back candidate for operator inspection and
// prunes the retained set down to the newest rejectedKeep files.
func (s *stateStore) saveRejected(generation uint64, raw []byte, reason string, at time.Time) (*rejectedRecord, error) {
	path := s.rejectedPath(generation)
	if err := renameio.WriteFile(path, raw, hotReloadFileMode); err != nil {
		return nil, err
	}
	s.pruneRejected(rejectedKeep)
	return &rejectedRecord{
		Generation: generation,
		At:         at,
		File:       filepath.Base(path),
		Reason:     reason,
	}, nil
}

func (s *stateStore) pruneRejected(keep int) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	type candidate struct {
		path string
		mod  time.Time
	}
	files := make([]candidate, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !isRejectedName(name) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, candidate{path: filepath.Join(s.dir, name), mod: info.ModTime()})
	}
	if len(files) <= keep {
		return
	}
	sort.Slice(files, func(i, j int) bool {
		if !files[i].mod.Equal(files[j].mod) {
			return files[i].mod.After(files[j].mod)
		}
		return files[i].path > files[j].path
	})
	for i := keep; i < len(files); i++ {
		_ = os.Remove(files[i].path)
	}
}

func isRejectedName(name string) bool {
	return len(name) > len(rejectedFilePrefix)+len(rejectedFileSuffix) &&
		filepath.Ext(name) == rejectedFileSuffix &&
		name[:len(rejectedFilePrefix)] == rejectedFilePrefix
}

// cleanupStaleTemp best-effort removes renameio leftovers ("."-prefixed
// regular files) from interrupted writes.
func (s *stateStore) cleanupStaleTemp() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if name := e.Name(); len(name) > 0 && name[0] == '.' && name != lockFileName {
			_ = os.Remove(filepath.Join(s.dir, name))
		}
	}
}

// withTransaction serializes promote/rollback/restore transactions across
// multiple dataplaneapi instances sharing one storage directory. Steady-state
// watching is never locked.
func (s *stateStore) withTransaction(fn func() error) error {
	lock, err := os.OpenFile(s.lockPath(), os.O_CREATE|os.O_RDWR, hotReloadFileMode)
	if err != nil {
		return err
	}
	defer func() {
		_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
		_ = lock.Close()
	}()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	return fn()
}

// isNotExist reports whether err is a missing-file error.
func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}
