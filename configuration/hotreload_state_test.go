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
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStateStore_CommitAndLoad(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "dataplaneapi.yaml"))
	if err := s.ensureDir(); err != nil {
		t.Fatal(err)
	}
	st := hotReloadState{Generation: 3, Fingerprint: "abc", ConfigPath: s.configPath, AcceptedAt: time.Now()}
	if err := s.commit(st); err != nil {
		t.Fatal(err)
	}
	got, foreign, err := s.load()
	if err != nil || foreign {
		t.Fatalf("load: err=%v foreign=%v", err, foreign)
	}
	if got.Generation != 3 || got.Fingerprint != "abc" || got.Version != hotReloadStateVer {
		t.Fatalf("unexpected state: %+v", got)
	}
}

func TestStateStore_CorruptAndUnknownSchema(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "dataplaneapi.yaml"))
	if err := s.ensureDir(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, s.statePath(), []byte("{not json"))
	if _, _, err := s.load(); err == nil {
		t.Fatal("expected corrupt state error")
	}
	writeFile(t, s.statePath(), []byte(`{"version":99,"generation":1,"fingerprint":"x","config_path":"`+s.configPath+`"}`))
	if _, _, err := s.load(); err == nil {
		t.Fatal("expected unsupported schema error")
	}
}

func TestStateStore_ForeignConfigPath(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "new.yaml"))
	if err := s.ensureDir(); err != nil {
		t.Fatal(err)
	}
	// Write the ledger directly: commit() always stamps the store's own path.
	writeFile(t, s.statePath(), []byte(`{"version":1,"generation":1,"fingerprint":"x","config_path":"/tmp/old.yaml"}`))
	_, foreign, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	if !foreign {
		t.Fatal("expected foreign ledger")
	}
}

func TestStateStore_BackupAndRestore(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "dataplaneapi.yaml")
	s := newStateStore(configPath)
	if err := s.ensureDir(); err != nil {
		t.Fatal(err)
	}
	payload := []byte("name: active\n")
	if err := s.writeBackup(payload); err != nil {
		t.Fatal(err)
	}
	if !s.backupExists() {
		t.Fatal("backup should exist")
	}
	writeFile(t, configPath, []byte("name: broken\n"))
	if err := s.restoreBackupTo(configPath); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(configPath)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("restore mismatch: %q err=%v", got, err)
	}
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != hotReloadFileMode {
		t.Fatalf("restored file mode = %o, want %o", info.Mode().Perm(), hotReloadFileMode)
	}
}

func TestStateStore_RejectedPruningAndModes(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "dataplaneapi.yaml"))
	if err := s.ensureDir(); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 7; i++ {
		rec, err := s.saveRejected(uint64(i), []byte{byte(i)}, "reason", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if rec == nil || !isRejectedName(rec.File) {
			t.Fatalf("bad rejected record: %+v", rec)
		}
		time.Sleep(2 * time.Millisecond) // ensure distinct mtimes for ordering
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	var kept int
	for _, e := range entries {
		if isRejectedName(e.Name()) {
			kept++
			info, err := e.Info()
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != hotReloadFileMode {
				t.Fatalf("rejected file mode %o", info.Mode().Perm())
			}
		}
	}
	if kept != rejectedKeep {
		t.Fatalf("expected %d rejected files kept, got %d", rejectedKeep, kept)
	}
}

func TestStateStore_CleanupStaleTemp(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "dataplaneapi.yaml"))
	if err := s.ensureDir(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(s.dir, ".state.json123-tmp"), []byte("x"))
	writeFile(t, filepath.Join(s.dir, "state.json"), []byte(`{}`))
	s.cleanupStaleTemp()
	if _, err := os.Stat(filepath.Join(s.dir, ".state.json123-tmp")); !os.IsNotExist(err) {
		t.Fatal("stale temp should be removed")
	}
	if _, err := os.Stat(filepath.Join(s.dir, "state.json")); err != nil {
		t.Fatal("state.json must remain")
	}
}

func TestStateStore_TransactionLock(t *testing.T) {
	s := newStateStore(filepath.Join(t.TempDir(), "dataplaneapi.yaml"))
	if err := s.ensureDir(); err != nil {
		t.Fatal(err)
	}
	ran := false
	if err := s.withTransaction(func() error {
		ran = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !ran {
		t.Fatal("transaction body did not run")
	}
}
