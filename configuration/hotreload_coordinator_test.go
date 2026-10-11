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
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- deterministic evaluateNow tests (no fsnotify, no timers) ---

func TestCoordinator_FirstStart_SeedsState(t *testing.T) {
	l := newLayout(t)
	tc := newTestCoordinator(t, l, validConfig(l, 8080), &fakeDeps{}, nil)
	st := tc.state()
	if st.Generation != 1 || st.Fingerprint == "" {
		t.Fatalf("expected seeded generation 1, got %+v", st)
	}
	if tc.reloads.Load() != 0 {
		t.Fatal("seeding must not reload")
	}
	backup, err := os.ReadFile(filepath.Join(tc.layout.stateDir(), backupFileName))
	if err != nil || !bytes.Equal(backup, validConfig(l, 8080)) {
		t.Fatalf("seed backup mismatch: err=%v", err)
	}
}

func TestCoordinator_UnchangedWriteSuppressed(t *testing.T) {
	l := newLayout(t)
	tc := newTestCoordinator(t, l, validConfig(l, 8080), &fakeDeps{}, nil)
	tc.writeConfig(validConfig(l, 8080))
	if out := tc.c.evaluateNow(context.Background()); out != OutcomeUnchanged {
		t.Fatalf("expected unchanged, got %s", out)
	}
	if tc.reloads.Load() != 0 {
		t.Fatal("unchanged content must not reload")
	}
}

func TestCoordinator_InvalidYAML_ThenRecovery(t *testing.T) {
	l := newLayout(t)
	tc := newTestCoordinator(t, l, validConfig(l, 8080), &fakeDeps{}, nil)
	bad := []byte("dataplaneapi:\n  port: [unterminated\n")
	tc.writeConfig(bad)
	if out := tc.c.evaluateNow(context.Background()); out != OutcomeInvalidYAML {
		t.Fatalf("expected invalid_yaml, got %s", out)
	}
	if tc.reloads.Load() != 0 {
		t.Fatal("invalid candidate must not reload")
	}
	// File left untouched for the operator to repair.
	if got := tc.readConfig(); !bytes.Equal(got, bad) {
		t.Fatal("invalid candidate file must not be modified")
	}
	st := tc.state()
	if st.Generation != 1 {
		t.Fatalf("active generation must stay 1, got %d", st.Generation)
	}

	// A subsequent valid write is accepted automatically.
	tc.writeConfig(validConfig(l, 9090))
	if out := tc.c.evaluateNow(context.Background()); out != OutcomeAccepted {
		t.Fatalf("expected accepted, got %s", out)
	}
	if tc.reloads.Load() != 1 {
		t.Fatal("valid candidate must reload exactly once")
	}
	if tc.state().Generation != 2 {
		t.Fatalf("expected generation 2")
	}
}

func TestCoordinator_InvalidFields_NoRestore_ThenRecovery(t *testing.T) {
	l := newLayout(t)
	tc := newTestCoordinator(t, l, validConfig(l, 8080), &fakeDeps{}, nil)
	bad := []byte("haproxy:\n  reload:\n    reload_strategy: bogus\n")
	tc.writeConfig(bad)
	if out := tc.c.evaluateNow(context.Background()); out != OutcomeInvalidFields {
		t.Fatalf("expected invalid_fields, got %s", out)
	}
	if got := tc.readConfig(); !bytes.Equal(got, bad) {
		t.Fatal("field-invalid file must not be rewritten")
	}
	tc.writeConfig(validConfig(l, 9091))
	if out := tc.c.evaluateNow(context.Background()); out != OutcomeAccepted {
		t.Fatalf("expected accepted after repair, got %s", out)
	}
}

func TestCoordinator_TransientMissingThenRecover(t *testing.T) {
	l := newLayout(t)
	tc := newTestCoordinator(t, l, validConfig(l, 8080), &fakeDeps{}, nil)
	tc.removeConfig()
	if out := tc.c.evaluateNow(context.Background()); out != OutcomeFileMissing {
		t.Fatalf("expected file_missing, got %s", out)
	}
	if tc.reloads.Load() != 0 || tc.state().Generation != 1 {
		t.Fatal("missing file must not change active state")
	}
	tc.writeConfig(validConfig(l, 9092))
	if out := tc.c.evaluateNow(context.Background()); out != OutcomeAccepted {
		t.Fatalf("expected accepted after recovery, got %s", out)
	}
}

func TestCoordinator_DepFailure_RollsBackAndSavesRejected(t *testing.T) {
	l := newLayout(t)
	active := validConfig(l, 8080)
	deps := &fakeDeps{fn: func(context.Context, *ValidatedCandidate) *GateError {
		return &GateError{Stage: GateDependency, Err: errors.New("boom: cert unreadable")}
	}}
	tc := newTestCoordinator(t, l, active, deps, nil)

	candidate := validConfig(l, 9093)
	tc.writeConfig(candidate)
	if out := tc.c.evaluateNow(context.Background()); out != OutcomeDependencyFailed {
		t.Fatalf("expected dependency_failed, got %s", out)
	}
	if tc.reloads.Load() != 0 {
		t.Fatal("dependency failure must not activate")
	}
	// Config path restored to the last active generation.
	if got := tc.readConfig(); !bytes.Equal(got, active) {
		t.Fatalf("config path should contain active backup, got %q", got)
	}
	// Rejected candidate preserved with 0600.
	rejected := tc.rejectedFiles()
	if len(rejected) != 1 {
		t.Fatalf("expected 1 rejected file, got %v", rejected)
	}
	info, err := os.Stat(filepath.Join(tc.layout.stateDir(), rejected[0]))
	if err != nil || info.Mode().Perm() != hotReloadFileMode {
		t.Fatalf("rejected mode: %v %o", err, info.Mode().Perm())
	}
	if tc.state().Generation != 1 {
		t.Fatal("active generation must not change on dep failure")
	}

	// Once the environment is fixed, new valid content is accepted.
	deps.fn = nil
	tc.writeConfig(validConfig(l, 9094))
	if out := tc.c.evaluateNow(context.Background()); out != OutcomeAccepted {
		t.Fatalf("expected acceptance after dep fix, got %s", out)
	}
	if tc.reloads.Load() != 1 {
		t.Fatal("expected one reload after recovery")
	}
}

func TestCoordinator_LostCallbackIdempotent(t *testing.T) {
	l := newLayout(t)
	tc := newTestCoordinator(t, l, validConfig(l, 8080), &fakeDeps{}, nil)
	candidate := validConfig(l, 9095)
	tc.writeConfig(candidate)
	if out := tc.c.evaluateNow(context.Background()); out != OutcomeAccepted {
		t.Fatalf("expected accepted, got %s", out)
	}
	// The restart/restart-equivalent callback was lost: re-evaluate identical
	// bytes and ensure components are not started a second time.
	tc.writeConfig(candidate)
	if out := tc.c.evaluateNow(context.Background()); out != OutcomeUnchanged {
		t.Fatalf("expected unchanged on duplicate, got %s", out)
	}
	if tc.reloads.Load() != 1 {
		t.Fatalf("identical fingerprint must not reload twice, got %d", tc.reloads.Load())
	}
}

func TestCoordinator_DuplicateFailureReportedOnce(t *testing.T) {
	l := newLayout(t)
	tc := newTestCoordinator(t, l, validConfig(l, 8080), &fakeDeps{}, nil)
	bad := []byte("dataplaneapi:\n  port: [unterminated\n")
	tc.writeConfig(bad)
	_ = tc.c.evaluateNow(context.Background())
	_ = tc.c.evaluateNow(context.Background())
	if n := tc.collect.count(OutcomeInvalidYAML); n != 1 {
		t.Fatalf("identical bad content should produce one event, got %d", n)
	}
	// Different bad content is reported again.
	other := []byte("dataplaneapi:\n  host: [\n")
	tc.writeConfig(other)
	_ = tc.c.evaluateNow(context.Background())
	if n := tc.collect.count(OutcomeInvalidYAML); n != 2 {
		t.Fatalf("different bad content should report again, got %d", n)
	}
}

func TestCoordinator_PostSaveResync_NoReload(t *testing.T) {
	l := newLayout(t)
	tc := newTestCoordinator(t, l, validConfig(l, 8080), &fakeDeps{}, nil)
	// Simulate a second boot where cfg.Save normalized the same content to
	// different bytes with a ledger already present.
	candidate := validConfig(l, 8080)
	candidate = append([]byte("# normalized by dataplaneapi\n"), candidate...)
	tc2 := spawnCoordinator(t, tc.params, candidate)
	if tc2.c.activeGen != 1 {
		t.Fatalf("resync must keep generation 1, got %d", tc2.c.activeGen)
	}
	if tc2.c.activeFP != fingerprint(candidate) {
		t.Fatal("resync must adopt the new fingerprint")
	}
	if tc2.reloads.Load() != 0 {
		t.Fatal("resync must not reload")
	}
}

// spawnCoordinator builds a second coordinator over the same params/storage.
func spawnCoordinator(t *testing.T, params HotReloadParams, disk []byte) *testCoordinator {
	t.Helper()
	writeFile(t, params.ConfigPath, disk)
	collect := newEventCollector()
	params.Observer = collect.observer
	tc := &testCoordinator{t: t, collect: collect, params: params}
	params.Reload = func() { tc.reloads.Add(1) }
	c, err := NewHotReloadCoordinator(params)
	if err != nil {
		t.Fatal(err)
	}
	tc.c = c
	return tc
}

// --- Run-loop tests with the controllable fake source ---

func TestCoordinator_NewerBurstSupersedesInFlight(t *testing.T) {
	l := newLayout(t)
	src := newFakeSource()
	// Slow gate for candidate A, so B lands while A is still validating.
	deps := &fakeDeps{delay: 80 * time.Millisecond, started: make(chan struct{}, 1)}
	tc := newTestCoordinator(t, l, validConfig(l, 8080), deps, src)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go tc.c.Run(ctx)

	// Generation A: distinct content. Debounce fires, slow check starts.
	tc.writeConfig(validConfig(l, 9100))
	src.trigger()
	select {
	case <-deps.started:
	case <-time.After(3 * time.Second):
		t.Fatal("candidate A evaluation never started")
	}

	// Generation B replaces A before the slow check returns.
	b := validConfig(l, 9101)
	tc.writeConfig(b)
	src.trigger()

	tc.collect.waitFor(t, OutcomeAccepted, 1, 3*time.Second)
	tc.collect.waitFor(t, OutcomeSuperseded, 1, 200*time.Millisecond)

	if tc.reloads.Load() != 1 {
		t.Fatalf("only the newest candidate must activate, reloads=%d", tc.reloads.Load())
	}
	if st := tc.state(); st.Generation != 2 || st.Fingerprint != fingerprint(b) {
		t.Fatalf("active state must be newest content: gen=%d fp=%s", st.Generation, st.Fingerprint)
	}
}

func TestCoordinator_WatchError_ReestablishesAndReevaluates(t *testing.T) {
	l := newLayout(t)
	src := newFakeSource()
	tc := newTestCoordinator(t, l, validConfig(l, 8080), &fakeDeps{}, src)
	params := tc.params
	rebuilt := make(chan struct{}, 1)
	// After the broken source reports an error, subsequent factories return
	// real fsnotify sources and signal that the watch is re-established.
	factoryCalls := 0
	params.NewSource = func(path string) (EventSource, error) {
		factoryCalls++
		if factoryCalls == 1 {
			return src, nil
		}
		s, err := newFSNotifySource(path)
		if err == nil {
			select {
			case rebuilt <- struct{}{}:
			default:
			}
		}
		return s, err
	}
	c, err := NewHotReloadCoordinator(params)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go c.Run(ctx)

	src.triggerErr(errors.New("inotify queue overflow"))
	// Wait for the new watch to be in place before replacing the file,
	// otherwise the replacement event would land in the rebuild window.
	select {
	case <-rebuilt:
	case <-time.After(3 * time.Second):
		t.Fatal("watcher was not re-established")
	}
	tmp := filepath.Join(l.root, "new.yaml")
	writeFile(t, tmp, validConfig(l, 9200))
	if err := os.Rename(tmp, l.configPath); err != nil {
		t.Fatal(err)
	}
	tc.collect.waitFor(t, OutcomeAccepted, 1, 3*time.Second)
	if tc.reloads.Load() != 1 {
		t.Fatal("re-evaluated content after watch re-establishment must activate")
	}
}

// --- real fsnotify behavioral tests ---

func TestCoordinator_InPlaceBurst_HalfWrittenThenValid(t *testing.T) {
	l := newLayout(t)
	tc := newTestCoordinator(t, l, validConfig(l, 8080), &fakeDeps{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go tc.c.Run(ctx)

	final := validConfig(l, 9300)
	// Truncate, write half the file, then complete it within the quiet window.
	f, err := os.OpenFile(l.configPath, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	half := len(final) / 2
	if _, err := f.Write(final[:half]); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	time.Sleep(10 * time.Millisecond)
	writeFile(t, l.configPath, final)

	tc.collect.waitFor(t, OutcomeAccepted, 1, 3*time.Second)
	if tc.reloads.Load() != 1 {
		t.Fatalf("burst must converge to one activation, reloads=%d", tc.reloads.Load())
	}
}

func TestCoordinator_AtomicRenameReplace(t *testing.T) {
	l := newLayout(t)
	tc := newTestCoordinator(t, l, validConfig(l, 8080), &fakeDeps{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go tc.c.Run(ctx)

	tmp := filepath.Join(l.root, "staged.yaml")
	writeFile(t, tmp, validConfig(l, 9400))
	if err := os.Rename(tmp, l.configPath); err != nil {
		t.Fatal(err)
	}
	tc.collect.waitFor(t, OutcomeAccepted, 1, 3*time.Second)
	if tc.reloads.Load() != 1 {
		t.Fatal("atomic rename replacement must activate once")
	}
}

func TestCoordinator_DeleteRecreate(t *testing.T) {
	l := newLayout(t)
	tc := newTestCoordinator(t, l, validConfig(l, 8080), &fakeDeps{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go tc.c.Run(ctx)

	if err := os.Remove(l.configPath); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	writeFile(t, l.configPath, validConfig(l, 9500))

	tc.collect.waitFor(t, OutcomeAccepted, 1, 3*time.Second)
	if tc.reloads.Load() != 1 {
		t.Fatal("delete+recreate must converge to one activation")
	}
}
