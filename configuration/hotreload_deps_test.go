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

func TestProductionDepChecker_ValidCandidate(t *testing.T) {
	clearOSOverrides(t)
	l := newLayout(t)
	v := NewProductionValidator(HAProxyConfiguration{}, ServerSettings{})
	cand, gateErr := v.Validate(validConfig(l, 8080))
	if gateErr != nil {
		t.Fatal(gateErr)
	}
	d := NewProductionDependencyChecker()
	if gerr := d.Check(context.Background(), cand); gerr != nil {
		t.Fatalf("expected deps ok, got %s: %v", gerr.Stage, gerr.Err)
	}
}

func TestProductionDepChecker_TLSFiles(t *testing.T) {
	clearOSOverrides(t)
	l := newLayout(t)
	certPath, keyPath, caPath := writeTestTLSPair(t, l.root)

	baseline := HAProxyConfiguration{ReloadStrategy: ReloadStratCustom, ReloadCmd: "true", RestartCmd: "true"}
	yaml := []byte(`dataplaneapi:
  user:
  - name: admin
    insecure: true
    password: adminpwd
  scheme:
  - https
  tls:
    tls_certificate: ` + certPath + `
    tls_key: ` + keyPath + `
    tls_ca: ` + caPath + `
`)
	v := NewProductionValidator(baseline, ServerSettings{})
	cand, gateErr := v.Validate(yaml)
	if gateErr != nil {
		t.Fatal(gateErr)
	}
	d := NewProductionDependencyChecker()
	if gerr := d.Check(context.Background(), cand); gerr != nil {
		t.Fatalf("expected TLS deps ok, got %s: %v", gerr.Stage, gerr.Err)
	}

	// Missing certificate file is a dependency failure, not a field failure.
	cand.Listen.TLSCertificate = filepath.Join(l.root, "missing.crt")
	gerr := d.Check(context.Background(), cand)
	if gerr == nil || gerr.Stage != GateDependency {
		t.Fatalf("expected dependency failure for missing cert, got %v", gerr)
	}

	// Corrupt CA content is a dependency failure.
	caCorrupt := filepath.Join(l.root, "bad-ca.pem")
	writeFile(t, caCorrupt, []byte("not a pem"))
	cand.Listen.TLSCertificate = certPath
	cand.Listen.TLSCACertificate = caCorrupt
	gerr = d.Check(context.Background(), cand)
	if gerr == nil || gerr.Stage != GateDependency {
		t.Fatalf("expected dependency failure for corrupt CA, got %v", gerr)
	}
}

func TestProductionDepChecker_UserlistSource(t *testing.T) {
	clearOSOverrides(t)
	l := newLayout(t)

	// Config without YAML users: the userlist file source is required.
	cfgPath := filepath.Join(l.root, "haproxy.cfg")
	yaml := []byte(`haproxy:
  config_file: ` + cfgPath + `
  reload:
    reload_cmd: "true"
    restart_cmd: "true"
`)
	baseline := HAProxyConfiguration{Userlist: "controller"}
	v := NewProductionValidator(baseline, ServerSettings{})
	cand, gateErr := v.Validate(yaml)
	if gateErr != nil {
		t.Fatal(gateErr)
	}
	d := NewProductionDependencyChecker()

	// Missing HAProxy config file -> dependency failure.
	if gerr := d.Check(context.Background(), cand); gerr == nil || gerr.Stage != GateDependency {
		t.Fatalf("expected dependency failure for missing userlist source, got %v", gerr)
	}

	writeFile(t, cfgPath, []byte(`userlist controller
    user admin
    insecure-password adminpwd
`))
	if gerr := d.Check(context.Background(), cand); gerr != nil {
		t.Fatalf("expected deps ok with userlist: %v", gerr)
	}

	// A file without the named userlist section fails too.
	writeFile(t, cfgPath, []byte("global\n    daemon\n"))
	if gerr := d.Check(context.Background(), cand); gerr == nil {
		t.Fatal("expected dependency failure when userlist section is absent")
	}
}

func TestProductionDepChecker_UnwritableDirectory(t *testing.T) {
	clearOSOverrides(t)
	if os.Geteuid() == 0 {
		t.Skip("permission checks are ineffective for root")
	}
	l := newLayout(t)
	blocked := filepath.Join(l.root, "blocked")
	if err := os.MkdirAll(blocked, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })

	baseline := HAProxyConfiguration{
		ReloadStrategy:     ReloadStratCustom,
		ReloadCmd:          "true",
		RestartCmd:         "true",
		DataplaneStorageDir: filepath.Join(blocked, "store"),
	}
	cand := &ValidatedCandidate{
		Effective: baseline,
		Listen:    ListenSettings{Schemes: []string{"http"}},
	}
	d := NewProductionDependencyChecker()
	if gerr := d.Check(context.Background(), cand); gerr == nil || gerr.Stage != GateDependency {
		t.Fatalf("expected dependency failure for unwritable dir, got %v", gerr)
	}
}
