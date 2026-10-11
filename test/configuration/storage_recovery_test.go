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

package clustermode_test

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/haproxytech/client-native/v6/models"
	"github.com/haproxytech/dataplaneapi/configuration"
	"github.com/haproxytech/dataplaneapi/storage"
	"github.com/stretchr/testify/require"
)

func setupRecoverableCfg(t *testing.T, dir string) *configuration.Configuration {
	t.Helper()
	cfgBytes, err := os.ReadFile(path.Join("expected", "dataplaneapi-1.yaml"))
	require.NoError(t, err)
	cfgPath := path.Join(dir, "dataplaneapi.yaml")
	require.NoError(t, os.WriteFile(cfgPath, cfgBytes, 0o600))

	cfg := initConfiguration(cfgPath, dir)
	_, err = cfg.Load()
	require.NoError(t, err)
	cfg.HAProxy.DataplaneStorageDir = dir
	return cfg
}

func consulStatePath(dir string) string {
	return filepath.Join(dir, storage.ConsulFileName)
}

func statusByName(t *testing.T, cfg *configuration.Configuration, name string) storage.StatusReport {
	t.Helper()
	for _, r := range cfg.StorageStatus() {
		if r.Name == name {
			return r
		}
	}
	require.Fail(t, "missing status for subsystem", name)
	return storage.StatusReport{}
}

func TestRecovery_CorruptConsulRestoredAndStartupSurvives(t *testing.T) {
	dir := t.TempDir()
	statePath := consulStatePath(dir)

	// Create two generations with tokens.
	store, err := storage.NewSDConsulStorage(statePath)
	require.NoError(t, err)
	require.NoError(t, store.AddConsulAndStore(&models.Consul{Name: "c1", Token: "secret-token-gen1"}))
	require.NoError(t, store.AddConsulAndStore(&models.Consul{Name: "c2", Token: "secret-token-gen2"}))

	// Truncate the active generation after the process died.
	b, err := os.ReadFile(statePath)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(statePath, b[:30], 0o600))

	cfg := setupRecoverableCfg(t, dir)
	msgs, err := cfg.LoadDataplaneStorageConfig()
	require.NoError(t, err, "one corrupt state file must not abort startup")

	require.Contains(t, strings.Join(msgs, "\n"), "[STORAGE RECOVERED] [consul]")
	require.Len(t, cfg.ServiceDiscovery.Consuls, 1)
	require.Equal(t, "c1", cfg.ServiceDiscovery.Consuls[0].Name)

	// Unrelated subsystems stay healthy.
	require.Equal(t, storage.Healthy, statusByName(t, cfg, storage.SubsystemAWS).State)
	require.Equal(t, storage.Healthy, statusByName(t, cfg, storage.SubsystemUsers).State)

	// The full configuration save must not fatally fail.
	require.NoError(t, cfg.Save())

	// Quarantine evidence exists but leaks no token.
	diagBytes, err := os.ReadDir(statePath + ".quarantine")
	require.NoError(t, err)
	require.NotEmpty(t, diagBytes)
	for _, en := range diagBytes {
		raw, err := os.ReadFile(filepath.Join(statePath+".quarantine", en.Name()))
		require.NoError(t, err)
		require.NotContains(t, string(raw), "secret-token-gen1")
		require.NotContains(t, string(raw), "secret-token-gen2")
	}
}

func TestRecovery_BothConsulCopiesInvalidIsolatesSubsystemOnly(t *testing.T) {
	dir := t.TempDir()
	statePath := consulStatePath(dir)

	store, err := storage.NewSDConsulStorage(statePath)
	require.NoError(t, err)
	require.NoError(t, store.AddConsulAndStore(&models.Consul{Name: "c1", Token: "secret-token-unavailable"}))
	require.NoError(t, store.AddConsulAndStore(&models.Consul{Name: "c2", Token: "secret-token-unavailable2"}))

	// Destroy both copies with unparseable content.
	require.NoError(t, os.WriteFile(statePath, []byte(`{"consuls":[{"token":"secret-token-unavailable2" <<< GARBAGE`), 0o600))
	require.NoError(t, os.WriteFile(statePath+".lkg", []byte("{garbage-lkg"), 0o600))

	cfg := setupRecoverableCfg(t, dir)
	msgs, err := cfg.LoadDataplaneStorageConfig()
	require.NoError(t, err, "an unavailable subsystem must not abort startup")
	require.Contains(t, strings.Join(msgs, "\n"), "[STORAGE UNAVAILABLE] [consul]")
	require.Empty(t, cfg.ServiceDiscovery.Consuls)

	st := statusByName(t, cfg, storage.SubsystemConsul)
	require.Equal(t, storage.Unavailable, st.State)
	require.False(t, st.State.Writable())

	// Users and AWS keep working.
	require.Equal(t, storage.Healthy, statusByName(t, cfg, storage.SubsystemAWS).State)
	require.Equal(t, storage.Healthy, statusByName(t, cfg, storage.SubsystemUsers).State)

	// Startup save skips the isolated store instead of failing.
	require.NoError(t, cfg.Save())

	// Evidence was preserved, not overwritten.
	raw, err := os.ReadFile(statePath)
	require.NoError(t, err)
	require.Contains(t, string(raw), "GARBAGE")

	for _, en := range mustReadQuarantine(t, statePath) {
		diag, err := os.ReadFile(filepath.Join(statePath+".quarantine", en.Name()))
		require.NoError(t, err)
		require.NotContains(t, string(diag), "secret-token-unavailable")
	}
}

func TestRecovery_UsersUnavailableDoesNotAffectConsul(t *testing.T) {
	dir := t.TempDir()

	// Healthy consul state.
	consulStore, err := storage.NewSDConsulStorage(consulStatePath(dir))
	require.NoError(t, err)
	require.NoError(t, consulStore.AddConsulAndStore(&models.Consul{Name: "c1", Token: "consul-token"}))

	// Destroy both copies of the users state.
	usersPath := filepath.Join(dir, storage.ClusterModeDataFileName)
	require.NoError(t, os.WriteFile(usersPath, []byte("{users-broken"), 0o600))
	require.NoError(t, os.WriteFile(usersPath+".lkg", []byte("{lkg-broken"), 0o600))

	cfg := setupRecoverableCfg(t, dir)
	_, err = cfg.LoadDataplaneStorageConfig()
	require.NoError(t, err)

	require.Equal(t, storage.Unavailable, statusByName(t, cfg, storage.SubsystemUsers).State)
	require.Equal(t, storage.Healthy, statusByName(t, cfg, storage.SubsystemConsul).State)
	require.Len(t, cfg.ServiceDiscovery.Consuls, 1)
}

func mustReadQuarantine(t *testing.T, statePath string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(statePath + ".quarantine")
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	return entries
}
