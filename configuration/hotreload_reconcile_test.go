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
	"context"
	"os"
	"path/filepath"
	"testing"
)

func reconcileParams(tc *testCoordinator, deps DependencyChecker) HotReloadParams {
	p := tc.params
	p.Deps = deps
	p.NewSource = nil
	p.Reload = nil
	p.Observer = nil
	return p
}

func TestReconcile_NoState_IsNoOp(t *testing.T) {
	clearOSOverrides(t)
	l := newLayout(t)
	writeFile(t, l.configPath, validConfig(l, 8080))
	res, err := ReconcileStartup(HotReloadParams{
		ConfigPath: l.configPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Ran || res.Action != ReconcileNone {
		t.Fatalf("expected no-op, got %+v", res)
	}
	if _, err := os.Stat(l.stateDir()); !os.IsNotExist(err) {
		t.Fatal("no ledger directory must be created on a legacy install")
	}
}

func TestReconcile_MatchAdoptsWithoutWrites(t *testing.T) {
	l := newLayout(t)
	tc := newTestCoordinator(t, l, validConfig(l, 8080), &fakeDeps{}, nil)
	res, err := ReconcileStartup(reconcileParams(tc, &fakeDeps{}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != ReconcileAdoptedMatch || res.Generation != 1 {
		t.Fatalf("expected adopted_match gen 1, got %+v", res)
	}
}

func TestReconcile_DiskValidMismatch_AdoptedDisk(t *testing.T) {
	l := newLayout(t)
	tc := newTestCoordinator(t, l, validConfig(l, 8080), &fakeDeps{}, nil)
	writeFile(t, l.configPath, validConfig(l, 8081))
	res, err := ReconcileStartup(reconcileParams(tc, &fakeDeps{}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != ReconcileAdoptedDisk || res.Generation != 2 {
		t.Fatalf("expected adopted_disk gen 2, got %+v", res)
	}
	if tc.state().Fingerprint != fingerprint(validConfig(l, 8081)) {
		t.Fatal("ledger should adopt the new disk fingerprint")
	}
	backup, err := os.ReadFile(filepath.Join(l.stateDir(), backupFileName))
	if err != nil || string(backup) != string(validConfig(l, 8081)) {
		t.Fatal("backup should equal adopted disk content")
	}
}

func TestReconcile_DiskInvalidMismatch_RestoredBackup(t *testing.T) {
	l := newLayout(t)
	active := validConfig(l, 8080)
	tc := newTestCoordinator(t, l, active, &fakeDeps{}, nil)
	writeFile(t, l.configPath, []byte("not: valid: yaml:"))
	res, err := ReconcileStartup(reconcileParams(tc, &fakeDeps{}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != ReconcileRestoredBackup || res.Generation != 1 {
		t.Fatalf("expected restored_backup gen 1, got %+v", res)
	}
	if got := tc.readConfig(); string(got) != string(active) {
		t.Fatal("disk must be restored to the last active generation")
	}
}

func TestReconcile_DepFailureMismatch_RestoredBackup(t *testing.T) {
	l := newLayout(t)
	active := validConfig(l, 8080)
	tc := newTestCoordinator(t, l, active, &fakeDeps{}, nil)
	writeFile(t, l.configPath, validConfig(l, 8082))
	deps := &fakeDeps{fn: func(context.Context, *ValidatedCandidate) *GateError {
		return &GateError{Stage: GateDependency, Err: os.ErrPermission}
	}}
	res, err := ReconcileStartup(reconcileParams(tc, deps))
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != ReconcileRestoredBackup {
		t.Fatalf("expected restored_backup on dep failure, got %+v", res)
	}
	if got := tc.readConfig(); string(got) != string(active) {
		t.Fatal("disk must be restored after startup dep failure")
	}
}

func TestReconcile_DiskMissing_RestoredBackup(t *testing.T) {
	l := newLayout(t)
	active := validConfig(l, 8080)
	tc := newTestCoordinator(t, l, active, &fakeDeps{}, nil)
	if err := os.Remove(l.configPath); err != nil {
		t.Fatal(err)
	}
	res, err := ReconcileStartup(reconcileParams(tc, &fakeDeps{}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != ReconcileRestoredBackup {
		t.Fatalf("expected restored_backup, got %+v", res)
	}
	if got := tc.readConfig(); string(got) != string(active) {
		t.Fatal("config must be restored from backup")
	}
}

func TestReconcile_InvalidMismatch_BackupMissing_HardError(t *testing.T) {
	l := newLayout(t)
	tc := newTestCoordinator(t, l, validConfig(l, 8080), &fakeDeps{}, nil)
	writeFile(t, l.configPath, []byte("bad: yaml: :"))
	if err := os.Remove(filepath.Join(l.stateDir(), backupFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReconcileStartup(reconcileParams(tc, &fakeDeps{})); err == nil {
		t.Fatal("expected hard error when disk is invalid and no backup exists")
	}
}

func TestReconcile_CorruptLedger_HardError(t *testing.T) {
	l := newLayout(t)
	tc := newTestCoordinator(t, l, validConfig(l, 8080), &fakeDeps{}, nil)
	writeFile(t, filepath.Join(l.stateDir(), stateFileName), []byte("{corrupt"))
	if _, err := ReconcileStartup(reconcileParams(tc, &fakeDeps{})); err == nil {
		t.Fatal("expected hard error on corrupt ledger")
	}
}

func TestReconcile_ForeignConfigPath_Ignored(t *testing.T) {
	l := newLayout(t)
	tc := newTestCoordinator(t, l, validConfig(l, 8080), &fakeDeps{}, nil)
	p := reconcileParams(tc, &fakeDeps{})
	p.ConfigPath = filepath.Join(l.root, "other.yaml")
	writeFile(t, p.ConfigPath, []byte("name: other\n"))
	// Pre-populate the other file's ledger with a state pointing elsewhere.
	foreign := newStateStore(p.ConfigPath)
	if err := foreign.ensureDir(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, foreign.statePath(), []byte(`{"version":1,"generation":1,"fingerprint":"x","config_path":"/tmp/different.yaml"}`))
	res, err := ReconcileStartup(p)
	if err != nil {
		t.Fatal(err)
	}
	if res.Ran || res.Action != ReconcileForeign {
		t.Fatalf("expected foreign no-op, got %+v", res)
	}
}
