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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/haproxytech/client-native/v6/misc"
	"github.com/haproxytech/client-native/v6/models"
	"github.com/haproxytech/dataplaneapi/storagetype"
	"github.com/stretchr/testify/require"
)

// ---- helpers ----

func newTestEngine[T Storable](t *testing.T, path, name string) *durableEngine[T] {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	e := &durableEngine[T]{
		name:     name,
		path:     path,
		lkgPath:  path + lkgSuffix,
		lockPath: path + lockSuffix,
		state:    Unavailable,
		since:    time.Now().UTC(),
	}
	e.open()
	return e
}

func clusterUsers(names ...string) storagetype.ClusterModeData {
	users := make(storagetype.Users, 0, len(names))
	for _, n := range names {
		pw := "pw-" + n + "-supersecret"
		users = append(users, storagetype.User{Name: n, Password: &pw})
	}
	return storagetype.ClusterModeData{Users: users}
}

func consulData(tokens ...string) storagetype.ConsulData {
	out := make(storagetype.Consuls, 0, len(tokens))
	for i, tk := range tokens {
		tk := tk
		name := fmt.Sprintf("consul-%d", i+1)
		out = append(out, &models.Consul{Name: name, Token: tk, Address: misc.StringP("127.0.0.1"), Port: misc.Int64P(8500), Enabled: misc.BoolP(true)})
	}
	return storagetype.ConsulData{Consuls: out}
}

func mustStore[T Storable](t *testing.T, e *durableEngine[T], data T) {
	t.Helper()
	require.NoError(t, e.Store(data))
}

func corruptFile(t *testing.T, path string, mutate func([]byte) []byte) {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, mutate(b), 0o600))
}

func truncateMain(t *testing.T, path string, keep int) {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	if keep > len(b) {
		keep = len(b)
	}
	require.NoError(t, os.WriteFile(path, b[:keep], 0o600))
}

// quarantineConcat reads every quarantine diagnostic for a state file.
func quarantineConcat(t *testing.T, mainPath string) string {
	t.Helper()
	dir := mainPath + quarantineDirSuffix
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return ""
	}
	require.NoError(t, err)
	var sb strings.Builder
	for _, en := range entries {
		b, err := os.ReadFile(filepath.Join(dir, en.Name()))
		require.NoError(t, err)
		sb.Write(b)
	}
	return sb.String()
}

func readEnvelopeGen(t *testing.T, path string) uint64 {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	var holder struct {
		DAPIMeta *struct {
			Generation uint64 `json:"generation"`
		} `json:"_dapi_meta"`
	}
	require.NoError(t, json.Unmarshal(b, &holder))
	require.NotNil(t, holder.DAPIMeta, "expected v2 envelope in %s", path)
	return holder.DAPIMeta.Generation
}

func assertPrivateMode(t *testing.T, path string, dir bool) {
	t.Helper()
	fi, err := os.Stat(path)
	require.NoError(t, err)
	if dir {
		require.Equal(t, os.FileMode(0o700), fi.Mode().Perm(), "directory %s", path)
	} else {
		require.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "file %s", path)
	}
}

// ---- tests ----

func TestEngine_FirstBootHealthyEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cluster.json")
	e := newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)

	require.Equal(t, Healthy, e.Status().State)
	require.Equal(t, uint64(0), e.Status().ActiveGeneration)
	require.Empty(t, e.Active().Users)
	_, err := os.Stat(path)
	require.True(t, os.IsNotExist(err))
}

func TestEngine_LegacyZeroByteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cluster.json")
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	e := newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)

	require.Equal(t, Healthy, e.Status().State)
	mustStore(t, e, clusterUsers("admin"))
	require.Equal(t, uint64(1), readEnvelopeGen(t, path))
}

func TestEngine_LegacyV1ReadAndLazyUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cluster.json")
	legacy := clusterUsers("admin", "user1")
	legacyBytes, err := json.Marshal(legacy) // bare object, no _dapi_meta
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, legacyBytes, 0o600))

	e := newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)
	require.Equal(t, Healthy, e.Status().State)
	require.Len(t, e.Active().Users, 2)

	// A successful write upgrades to the integrity-enabled v2 envelope.
	upgraded := clusterUsers("admin", "user1", "user2")
	mustStore(t, e, upgraded)
	require.Equal(t, uint64(1), readEnvelopeGen(t, path))

	// Legacy readers unmarshalling the file directly keep working.
	var direct storagetype.ClusterModeData
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &direct))
	require.Len(t, direct.Users, 3)
	require.Equal(t, "user2", direct.Users[2].Name)
}

func TestEngine_MonotonicGenerations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consul.json")
	e := newTestEngine[storagetype.ConsulData](t, path, SubsystemConsul)
	for i := 1; i <= 3; i++ {
		tokens := make([]string, i)
		for j := range tokens {
			tokens[j] = fmt.Sprintf("token-%d", j+1)
		}
		mustStore(t, e, consulData(tokens...))
		require.Equal(t, uint64(i), e.Status().ActiveGeneration)
	}
	// A fresh process confirms the highest generation.
	e2 := newTestEngine[storagetype.ConsulData](t, path, SubsystemConsul)
	require.Equal(t, Healthy, e2.Status().State)
	require.Equal(t, uint64(3), e2.Status().ActiveGeneration)
	require.Len(t, e2.Active().Consuls, 3)
}

func TestEngine_RereadVerificationRejectsTamperedChecksum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aws.json")
	e := newTestEngine[storagetype.AWSRegionData](t, path, SubsystemAWS)
	mustStore(t, e, storagetype.AWSRegionData{AWSRegions: storagetype.AWSRegions{}})
	r2 := storagetype.AWSRegionData{AWSRegions: storagetype.AWSRegions{
		&models.AwsRegion{Name: misc.StringP("eu"), AccessKeyID: "AKIA-LEGIT", SecretAccessKey: "secret-access-key-xyz"},
	}}
	mustStore(t, e, r2)

	// Tamper with the active generation while keeping it valid JSON:
	// checksum verification must fail on recovery.
	corruptFile(t, path, func(b []byte) []byte {
		return []byte(strings.Replace(string(b), "secret-access-key-xyz", "tampered-key-value", 1))
	})

	e2 := newTestEngine[storagetype.AWSRegionData](t, path, SubsystemAWS)
	require.Equal(t, Recovered, e2.Status().State)
	require.Equal(t, uint64(1), e2.Status().ActiveGeneration)
	require.Empty(t, e2.Active().AWSRegions)
	require.Equal(t, uint64(1), readEnvelopeGen(t, path))
}

func TestEngine_TruncatedMainRestoresLKG(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cluster.json")
	e := newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)
	g1 := clusterUsers("alice")
	mustStore(t, e, g1)
	mustStore(t, e, clusterUsers("alice", "bob"))
	require.Equal(t, uint64(2), e.Status().ActiveGeneration)

	// Simulate a torn/truncated write of the active file.
	truncateMain(t, path, 40)

	e2 := newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)
	require.Equal(t, Recovered, e2.Status().State, "detail: %s", e2.Status().Detail)
	require.Equal(t, uint64(1), e2.Status().ActiveGeneration)
	require.Equal(t, g1.Users, e2.Active().Users)
	require.Equal(t, uint64(1), readEnvelopeGen(t, path))

	// Writes work again after recovery; evidence is kept safely.
	mustStore(t, e2, clusterUsers("alice", "carol"))
	require.Equal(t, Healthy, e2.Status().State)
	diag := quarantineConcat(t, path)
	require.NotEmpty(t, diag)
	require.NotContains(t, diag, "pw-alice-supersecret")
}

func TestEngine_ZeroByteMainWithLKGRecovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cluster.json")
	e := newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)
	g1 := clusterUsers("alice")
	mustStore(t, e, g1)
	mustStore(t, e, clusterUsers("alice", "bob"))
	require.NoError(t, os.WriteFile(path, []byte{}, 0o600))

	e2 := newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)
	require.Equal(t, Recovered, e2.Status().State)
	require.Equal(t, g1.Users, e2.Active().Users)
	require.Equal(t, uint64(1), readEnvelopeGen(t, path))
}

func TestEngine_BothCopiesInvalidIsolatesAndPreservesEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consul.json")
	e := newTestEngine[storagetype.ConsulData](t, path, SubsystemConsul)
	mustStore(t, e, consulData("very-secret-token-value"))

	garbageMain := append([]byte(`{"consuls":[{"token":"very-secret-token-value"`), []byte(" <<< truncated garbage ZZZMARKER")...)
	garbageLKG := []byte("{not json at all LKGMARKER")
	require.NoError(t, os.WriteFile(path, garbageMain, 0o600))
	require.NoError(t, os.WriteFile(path+lkgSuffix, garbageLKG, 0o600))

	e2 := newTestEngine[storagetype.ConsulData](t, path, SubsystemConsul)
	require.Equal(t, Unavailable, e2.Status().State)
	require.Empty(t, e2.Active().Consuls)

	// Writes are rejected; evidence must never be overwritten.
	err := e2.Store(consulData("new"))
	require.ErrorIs(t, err, ErrStorageUnavailable)
	mainAfter, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, garbageMain, mainAfter)
	lkgAfter, err := os.ReadFile(path + lkgSuffix)
	require.NoError(t, err)
	require.Equal(t, garbageLKG, lkgAfter)

	// Diagnostics exist but contain neither raw garbage nor the token.
	diag := quarantineConcat(t, path)
	require.NotEmpty(t, diag)
	require.NotContains(t, diag, "very-secret-token-value")
	require.NotContains(t, diag, "ZZZMARKER")
	require.NotContains(t, diag, "LKGMARKER")
}

func TestEngine_QuarantineRedactsParseableContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consul.json")
	e := newTestEngine[storagetype.ConsulData](t, path, SubsystemConsul)
	mustStore(t, e, consulData("t1"))
	mustStore(t, e, consulData("t1", "t2-token-to-hide"))

	// Valid JSON, wrong checksum: redacted_content is present but the
	// token must not leak.
	corruptFile(t, path, func(b []byte) []byte {
		return []byte(strings.Replace(string(b), "t2-token-to-hide", "CHANGED-TOKEN-EVIDENCE", 1))
	})
	e2 := newTestEngine[storagetype.ConsulData](t, path, SubsystemConsul)
	require.Equal(t, Recovered, e2.Status().State)

	diag := quarantineConcat(t, path)
	require.Contains(t, diag, redactedValue)
	require.NotContains(t, diag, "CHANGED-TOKEN-EVIDENCE")
	require.NotContains(t, diag, "t1") // the older token must not leak either
}

func TestEngine_CrashWindowIntactCandidateIsConfirmed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cluster.json")
	// Process 1 wrote gen1 (lkg promoted on next open) — emulate crash
	// between candidate flush and confirmation: intact newer main.
	e1 := newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)
	mustStore(t, e1, clusterUsers("g1"))

	// Manually craft a gen2 main (intact) without lkg refresh, as if the
	// process died right after the rename.
	g2 := clusterUsers("g1", "g2")
	encoded, err := encodeGeneration(g2, 2)
	require.NoError(t, err)
	require.NoError(t, atomicWrite(path, encoded))

	e2 := newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)
	require.Equal(t, Healthy, e2.Status().State)
	require.Equal(t, uint64(2), e2.Status().ActiveGeneration)
	require.Len(t, e2.Active().Users, 2)
}

func TestEngine_PreCommitFailureIsRetryable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cluster.json")
	e := newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)
	g1 := clusterUsers("alice")
	mustStore(t, e, g1)

	e.hookBeforeCommit = func() error { return errors.New("disk full simulated") }
	err := e.Store(clusterUsers("alice", "bob"))
	require.ErrorIs(t, err, ErrWritePending)
	require.Equal(t, Healthy, e.Status().State)
	require.Equal(t, g1.Users, e.Active().Users, "failed write must not change the active object")
	require.Equal(t, uint64(1), readEnvelopeGen(t, path))

	e.hookBeforeCommit = nil
	mustStore(t, e, clusterUsers("alice", "bob"))
	require.Equal(t, uint64(2), readEnvelopeGen(t, path))
}

func TestEngine_PostCommitVerifyFailureFallsBackToLKG(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cluster.json")
	e := newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)
	g1 := clusterUsers("alice")
	mustStore(t, e, g1)

	e.hookAfterCommit = func() error {
		// Torn candidate right after the atomic rename.
		truncateMain(t, path, 20)
		return nil
	}
	g2 := clusterUsers("alice", "bob")
	err := e.Store(g2)
	require.ErrorIs(t, err, ErrGenerationVerifyFailed)
	require.Equal(t, Recovered, e.Status().State)
	require.Equal(t, g1.Users, e.Active().Users, "active must be the last known good generation, not the failed candidate")
	require.Equal(t, uint64(1), readEnvelopeGen(t, path))

	e.hookAfterCommit = nil
	mustStore(t, e, clusterUsers("alice", "carol"))
	require.Equal(t, Healthy, e.Status().State)
	require.Equal(t, uint64(2), readEnvelopeGen(t, path))
}

func TestEngine_RestoreWriteFailureBecomesReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cluster.json")
	e := newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)
	g1 := clusterUsers("alice")
	mustStore(t, e, g1)

	e.hookAfterCommit = func() error {
		truncateMain(t, path, 20)
		return nil
	}
	e.hookBeforeRestore = func() error { return errors.New("cannot restore: disk full") }

	err := e.Store(clusterUsers("alice", "bob"))
	require.ErrorIs(t, err, ErrReadOnly)
	require.Equal(t, ReadOnlyIsolated, e.Status().State)
	require.Equal(t, g1.Users, e.Active().Users, "LKG reads must still be served from memory")

	err = e.Store(clusterUsers("other"))
	require.ErrorIs(t, err, ErrReadOnly)
	require.Equal(t, g1.Users, e.Active().Users)
}

func TestEngine_StaleGenerationDoesNotOverwriteNewer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cluster.json")
	a := newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)
	mustStore(t, a, clusterUsers("base"))
	// B opens on the same path (like a second process) and learns gen 1.
	b := newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)
	require.Equal(t, uint64(1), b.Status().ActiveGeneration)

	// A commits gen 2 first.
	newer := clusterUsers("base", "from-a")
	mustStore(t, a, newer)

	// B's candidate is based on the stale gen 1: it must be rejected and
	// B must adopt the newer generation instead of overwriting it.
	err := b.Store(clusterUsers("base", "from-b"))
	require.ErrorIs(t, err, ErrStaleGeneration)
	require.Equal(t, uint64(2), b.Status().ActiveGeneration)
	require.Equal(t, newer.Users, b.Active().Users)

	onDisk := newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)
	require.Equal(t, newer.Users, onDisk.Active().Users)
}

func TestEngine_ConcurrentStoresSerialise(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cluster.json")
	e := newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)
	mustStore(t, e, clusterUsers("seed"))

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- e.Store(clusterUsers("seed")) // identical full-state writes
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, uint64(21), e.Status().ActiveGeneration)
	// The final on-disk generation verifies cleanly.
	final := newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)
	require.Equal(t, Healthy, final.Status().State)
	require.Equal(t, uint64(21), final.Status().ActiveGeneration)
}

func TestEngine_StaleTemporaryFilesAreSwept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cluster.json")
	e := newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)
	mustStore(t, e, clusterUsers("alice"))

	stale := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".stale12345")
	require.NoError(t, os.WriteFile(stale, []byte("pending"), 0o600))
	_ = newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)
	_, err := os.Stat(stale)
	require.True(t, os.IsNotExist(err), "stale renameio temp must be swept")
}

func TestEngine_ArtifactPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cluster.json")
	e := newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)
	mustStore(t, e, clusterUsers("alice"))
	mustStore(t, e, clusterUsers("alice", "bob"))
	assertPrivateMode(t, path, false)
	assertPrivateMode(t, path+lkgSuffix, false)
	assertPrivateMode(t, path+lockSuffix, false)

	truncateMain(t, path, 10)
	_ = newTestEngine[storagetype.ClusterModeData](t, path, SubsystemUsers)
	assertPrivateMode(t, path+quarantineDirSuffix, true)
	entries, err := os.ReadDir(path + quarantineDirSuffix)
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	for _, en := range entries {
		assertPrivateMode(t, filepath.Join(path+quarantineDirSuffix, en.Name()), false)
	}
}
