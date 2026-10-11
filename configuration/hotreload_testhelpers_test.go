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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/renameio"
)

// clearOSOverrides ensures candidate YAML fields are not masked during tests
// by leftover CLI args or HOST/PORT/TLS environment variables.
func clearOSOverrides(t *testing.T) {
	t.Helper()
	savedArgs := os.Args
	savedEnv := map[string]string{}
	envNames := []string{"HOST", "PORT", "TLS_HOST", "TLS_PORT", "TLS_CERTIFICATE", "TLS_PRIVATE_KEY", "TLS_CA_CERTIFICATE"}
	for _, name := range envNames {
		if v, ok := os.LookupEnv(name); ok {
			savedEnv[name] = v
		}
		_ = os.Unsetenv(name)
	}
	os.Args = []string{"dataplaneapi.test"}
	t.Cleanup(func() {
		os.Args = savedArgs
		for name, v := range savedEnv {
			_ = os.Setenv(name, v)
		}
	})
}

// testLayout centralizes the paths used by a test deployment.
type testLayout struct {
	root       string
	configPath string
	storageDir string
}

func newLayout(t *testing.T) testLayout {
	t.Helper()
	root := t.TempDir()
	return testLayout{
		root:       root,
		configPath: filepath.Join(root, "dataplaneapi.yaml"),
		storageDir: filepath.Join(root, "store"),
	}
}

// stateDir is the ledger directory: <config dir>/.dataplaneapi.yaml.hotreload.
func (l testLayout) stateDir() string {
	return filepath.Join(filepath.Dir(l.configPath),
		fmt.Sprintf(hotReloadDirNamePattern, filepath.Base(l.configPath)))
}

// validConfig renders a config that passes the production validator and
// dependency checker. port differentiates content between generations.
func validConfig(l testLayout, port int) []byte {
	return []byte(fmt.Sprintf(`dataplaneapi:
  host: 127.0.0.1
  port: %d
  user:
  - name: admin
    insecure: true
    password: adminpwd
  resources:
    maps_dir: %[2]s/maps
    ssl_certs_dir: %[2]s/ssl
    general_storage_dir: %[2]s/general
    dataplane_storage_dir: %[2]s/store
    spoe_dir: %[2]s/spoe
    spoe_transaction_dir: %[2]s/spoe-tx
  transaction:
    transaction_dir: %[2]s/tmp
    backups_dir: %[2]s/backups
haproxy:
  config_file: %[3]s/haproxy.cfg
  reload:
    reload_cmd: "true"
    restart_cmd: "true"
`, port, l.root, l.root))
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := renameio.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// testCoordinator bundles a running-ready coordinator with its probes.
type testCoordinator struct {
	t       *testing.T
	layout  testLayout
	c       *HotReloadCoordinator
	params  HotReloadParams
	reloads atomic.Int32
	collect *eventCollector
	source  *fakeSource
}

type eventCollector struct {
	mu     sync.Mutex
	events []ObservedEvent
	notify chan struct{}
}

func newEventCollector() *eventCollector {
	return &eventCollector{notify: make(chan struct{}, 1024)}
}

func (e *eventCollector) observer(ev ObservedEvent) {
	e.mu.Lock()
	e.events = append(e.events, ev)
	e.mu.Unlock()
	select {
	case e.notify <- struct{}{}:
	default:
	}
}

func (e *eventCollector) count(o Outcome) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, ev := range e.events {
		if ev.Outcome == o {
			n++
		}
	}
	return n
}

func (e *eventCollector) fingerprints(o Outcome) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, ev := range e.events {
		if ev.Outcome == o {
			out = append(out, ev.Fingerprint)
		}
	}
	return out
}

// waitFor blocks until at least n events of outcome o were observed.
func (e *eventCollector) waitFor(t *testing.T, o Outcome, n int, timeout time.Duration) []ObservedEvent {
	t.Helper()
	deadline := time.After(timeout)
	for {
		if got := e.count(o); got >= n {
			e.mu.Lock()
			var matched []ObservedEvent
			for _, ev := range e.events {
				if ev.Outcome == o {
					matched = append(matched, ev)
				}
			}
			e.mu.Unlock()
			return matched
		}
		select {
		case <-e.notify:
		case <-deadline:
			t.Fatalf("timed out waiting for %d %q events (got %d)", n, o, e.count(o))
		case <-time.After(10 * time.Millisecond):
		}
	}
}

type fakeDeps struct {
	fn      func(context.Context, *ValidatedCandidate) *GateError
	delay   time.Duration
	started chan struct{}
}

func (f *fakeDeps) Check(ctx context.Context, v *ValidatedCandidate) *GateError {
	if f.started != nil {
		select {
		case f.started <- struct{}{}:
		default:
		}
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return &GateError{Stage: GateDependency, Err: ctx.Err()}
		}
	}
	if f.fn != nil {
		return f.fn(ctx, v)
	}
	return nil
}

// fakeSource is a manually controlled event source replacing fsnotify.
type fakeSource struct {
	dirty  chan struct{}
	errs   chan error
	closed atomic.Bool
}

func newFakeSource() *fakeSource {
	return &fakeSource{dirty: make(chan struct{}, 16), errs: make(chan error, 4)}
}

func (f *fakeSource) Dirty() <-chan struct{} { return f.dirty }
func (f *fakeSource) Errors() <-chan error   { return f.errs }
func (f *fakeSource) Close() error           { f.closed.Store(true); return nil }

func (f *fakeSource) trigger() {
	select {
	case f.dirty <- struct{}{}:
	default:
	}
}

func (f *fakeSource) triggerErr(err error) {
	select {
	case f.errs <- err:
	default:
	}
}

func newTestCoordinator(t *testing.T, l testLayout, initial []byte, deps DependencyChecker, src *fakeSource) *testCoordinator {
	t.Helper()
	clearOSOverrides(t)
	if err := os.MkdirAll(filepath.Dir(l.configPath), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, l.configPath, initial)

	collect := newEventCollector()
	params := HotReloadParams{
		ConfigPath: l.configPath,
		Debounce:   20 * time.Millisecond,
		Deps:       deps,
		Observer:   collect.observer,
	}
	if src != nil {
		params.NewSource = func(string) (EventSource, error) { return src, nil }
	}
	tc := &testCoordinator{t: t, layout: l, collect: collect, source: src}
	params.Reload = func() { tc.reloads.Add(1) }
	tc.params = params

	c, err := NewHotReloadCoordinator(params)
	if err != nil {
		t.Fatalf("new coordinator: %v", err)
	}
	tc.c = c
	return tc
}

// writeConfig replaces the config content (atomic rename semantics).
func (tc *testCoordinator) writeConfig(data []byte) {
	writeFile(tc.t, tc.layout.configPath, data)
}

// removeConfig deletes the config file.
func (tc *testCoordinator) removeConfig() {
	if err := os.Remove(tc.layout.configPath); err != nil {
		tc.t.Fatal(err)
	}
}

func (tc *testCoordinator) readConfig() []byte {
	data, err := os.ReadFile(tc.layout.configPath)
	if err != nil {
		tc.t.Fatal(err)
	}
	return data
}

func (tc *testCoordinator) state() *hotReloadState {
	st, _, err := tc.c.store.load()
	if err != nil {
		tc.t.Fatal(err)
	}
	return st
}

// rejectedFiles lists preserved rejected candidates.
func (tc *testCoordinator) rejectedFiles() []string {
	entries, err := os.ReadDir(tc.layout.stateDir())
	if err != nil {
		tc.t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if isRejectedName(e.Name()) {
			names = append(names, e.Name())
		}
	}
	return names
}

func writeTestTLSPair(t *testing.T, dir string) (certPath, keyPath, caPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dataplaneapi-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	cf, err := os.OpenFile(certPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	_ = cf.Close()

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	kf, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatal(err)
	}
	_ = kf.Close()
	return certPath, keyPath, certPath
}
