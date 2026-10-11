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
	"strconv"
	"strings"
	"testing"
)

func TestValidator_ValidConfig(t *testing.T) {
	clearOSOverrides(t)
	l := newLayout(t)
	v := NewProductionValidator(HAProxyConfiguration{}, ServerSettings{})
	cand, gateErr := v.Validate(validConfig(l, 8080))
	if gateErr != nil {
		t.Fatalf("expected valid candidate, got %s: %v", gateErr.Stage, gateErr.Err)
	}
	if len(cand.Listen.Schemes) != 1 || cand.Listen.Schemes[0] != "http" {
		t.Fatalf("expected default [http] scheme, got %v", cand.Listen.Schemes)
	}
	if cand.Listen.Port != 8080 {
		t.Fatalf("expected port 8080, got %d", cand.Listen.Port)
	}
	if cand.Effective.ReloadCmd != "true" || cand.Effective.RestartCmd != "true" {
		t.Fatalf("reload commands not applied: %+v", cand.Effective)
	}
	if cand.Fingerprint == "" || len(cand.Users) != 1 {
		t.Fatalf("fingerprint/users wrong: fp=%q users=%d", cand.Fingerprint, len(cand.Users))
	}
}

func TestValidator_InvalidYAML(t *testing.T) {
	clearOSOverrides(t)
	v := NewProductionValidator(HAProxyConfiguration{}, ServerSettings{})
	_, gateErr := v.Validate([]byte("dataplaneapi:\n  port: [\n"))
	if gateErr == nil || gateErr.Stage != GateYAML {
		t.Fatalf("expected GateYAML, got %v", gateErr)
	}
}

func TestValidator_FieldCases(t *testing.T) {
	clearOSOverrides(t)
	tests := []struct {
		name      string
		yaml      string
		cmds      bool
		wantInErr string
	}{
		{
			name:      "custom strategy without commands",
			yaml:      "haproxy:\n  reload: {}\n",
			cmds:      false,
			wantInErr: "ReloadCmd",
		},
		{
			name:      "invalid reload strategy",
			yaml:      "haproxy:\n  reload:\n    reload_strategy: bogus\n",
			cmds:      true,
			wantInErr: "invalid reload strategy",
		},
		{
			name: "duplicate users",
			yaml: `dataplaneapi:
  user:
  - name: admin
    insecure: true
    password: a
  - name: admin
    insecure: true
    password: b
`,
			cmds:      true,
			wantInErr: "duplicate user",
		},
		{
			name: "empty user name",
			yaml: `dataplaneapi:
  user:
  - name: ""
    insecure: true
    password: a
`,
			cmds:      true,
			wantInErr: "empty name",
		},
		{
			name: "plaintext password without insecure",
			yaml: `dataplaneapi:
  user:
  - name: admin
    insecure: false
    password: plaintext
`,
			cmds:      true,
			wantInErr: "must be a hashed value",
		},
		{
			name:      "invalid port",
			yaml:      "dataplaneapi:\n  port: 70000\n",
			cmds:      true,
			wantInErr: "invalid port",
		},
		{
			name:      "invalid scheme",
			yaml:      "dataplaneapi:\n  scheme:\n  - gopher\n",
			cmds:      true,
			wantInErr: "invalid listener scheme",
		},
		{
			name: "https without certificates",
			yaml: `dataplaneapi:
  scheme:
  - https
`,
			cmds:      true,
			wantInErr: "https listener requires",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Baseline carries reload commands unless the case specifically
			// exercises their absence, so the error under test is the only one.
			baseline := HAProxyConfiguration{}
			baseline.ReloadStrategy = ReloadStratCustom
			if tc.cmds {
				baseline.ReloadCmd = "true"
				baseline.RestartCmd = "true"
			}
			v := NewProductionValidator(baseline, ServerSettings{})
			_, gateErr := v.Validate([]byte(tc.yaml))
			if gateErr == nil {
				t.Fatalf("expected gate failure for %q", tc.name)
			}
			if gateErr.Stage != GateFields {
				t.Fatalf("%s: expected GateFields, got %s: %v", tc.name, gateErr.Stage, gateErr.Err)
			}
			if !strings.Contains(gateErr.Err.Error(), tc.wantInErr) {
				t.Fatalf("%s: error %q does not contain %q", tc.name, gateErr.Err.Error(), tc.wantInErr)
			}
		})
	}
}

func TestValidator_HashedSecretShapes(t *testing.T) {
	clearOSOverrides(t)
	baseline := HAProxyConfiguration{ReloadStrategy: ReloadStratCustom, ReloadCmd: "true", RestartCmd: "true"}
	valid := []string{
		`$6$salt$hashvaluehashvaluehashvaluehashvaluehashvaluehashvalue0`,
		`$5$salt$hashvaluehashvaluehashvaluehashvaluehashvaluehashvalue0`,
		`$1$salt$hashvaluehashvalue00`,
		`"${ADMIN_PASSWORD}"`,
	}
	v := NewProductionValidator(baseline, ServerSettings{})
	for _, pw := range valid {
		yaml := "dataplaneapi:\n  user:\n  - name: admin\n    insecure: false\n    password: " + strconv.Quote(pw) + "\n"
		if _, gateErr := v.Validate([]byte(yaml)); gateErr != nil {
			t.Fatalf("expected %s accepted: %v", pw, gateErr)
		}
	}
}

func TestValidator_ConsulMissingIDAssigned(t *testing.T) {
	clearOSOverrides(t)
	baseline := HAProxyConfiguration{ReloadStrategy: ReloadStratCustom, ReloadCmd: "true", RestartCmd: "true"}
	yaml := `service_discovery:
  consuls:
  - address: "127.0.0.1"
    name: "consul1"
    enabled: true
    port: 8500
    retrytimeout: 10
    serverslotsbase: 10
`
	v := NewProductionValidator(baseline, ServerSettings{})
	cand, gateErr := v.Validate([]byte(yaml))
	if gateErr != nil {
		t.Fatalf("expected valid, got %s: %v", gateErr.Stage, gateErr.Err)
	}
	consuls := *cand.Parsed.DeprecatedServiceDiscovery.Consuls
	if consuls[0].ID == nil || *consuls[0].ID == "" {
		t.Fatal("expected UUID to be assigned")
	}
}

func TestValidator_ConsulInvalid(t *testing.T) {
	clearOSOverrides(t)
	baseline := HAProxyConfiguration{ReloadStrategy: ReloadStratCustom, ReloadCmd: "true", RestartCmd: "true"}
	yaml := `service_discovery:
  consuls:
  - address: ""
    name: "consul1"
    enabled: true
    port: 99999
    id: "11111111-1111-1111-1111-111111111111"
    retrytimeout: 10
`
	v := NewProductionValidator(baseline, ServerSettings{})
	_, gateErr := v.Validate([]byte(yaml))
	if gateErr == nil || gateErr.Stage != GateFields {
		t.Fatalf("expected field gate failure, got %v", gateErr)
	}
}

func TestValidator_CLIOverrideMasksYAMLPort(t *testing.T) {
	clearOSOverrides(t)
	os.Args = []string{"dataplaneapi.test", "--port=9090"}

	v := NewProductionValidator(HAProxyConfiguration{}, ServerSettings{Port: 9090})
	l := newLayout(t)
	cand, gateErr := v.Validate(validConfig(l, 8080))
	if gateErr != nil {
		t.Fatalf("unexpected gate error: %v", gateErr)
	}
	if cand.Listen.Port != 9090 {
		t.Fatalf("CLI port must win over YAML, got %d", cand.Listen.Port)
	}
}
