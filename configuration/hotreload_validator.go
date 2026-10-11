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
	"errors"
	"fmt"
	"slices"
	"strings"

	flags "github.com/jessevdk/go-flags"
	"gopkg.in/yaml.v2"

	"github.com/haproxytech/dataplaneapi/discovery"
	"github.com/haproxytech/dataplaneapi/misc"
)

// GateStage pinpoints which validation gate rejected a candidate, keeping
// syntax failures, field failures and dependency failures distinguishable.
type GateStage int

const (
	GateYAML GateStage = iota
	GateFields
	GateDependency
)

func (s GateStage) String() string {
	switch s {
	case GateYAML:
		return "yaml"
	case GateFields:
		return "fields"
	case GateDependency:
		return "dependencies"
	default:
		return "unknown"
	}
}

// GateError is a candidate rejection at a specific gate.
type GateError struct {
	Stage GateStage
	Err   error
}

func (e *GateError) Error() string {
	return fmt.Sprintf("hot-reload %s gate failed: %s", e.Stage, e.Err.Error())
}

func (e *GateError) Unwrap() error { return e.Err }

// ValidatedCandidate is the fully validated, ready-to-activate snapshot.
type ValidatedCandidate struct {
	Candidate

	Parsed    *StorageDataplaneAPIConfiguration
	Effective HAProxyConfiguration
	Listen    ListenSettings
	Users     []User
}

// CandidateValidator runs gates 2 (syntax) and 3 (field validation).
type CandidateValidator interface {
	Validate(raw []byte) (*ValidatedCandidate, *GateError)
}

type productionValidator struct {
	cli      HAProxyConfiguration
	server   ServerSettings
}

func NewProductionValidator(cli HAProxyConfiguration, srv ServerSettings) CandidateValidator {
	return &productionValidator{cli: cli, server: srv}
}

// Validate never touches the global Configuration singleton: the production
// mapping and reload-strategy validation run on a throwaway probe built from
// the post-Parse CLI baseline, exactly reproducing what the next restart
// would derive from the candidate bytes.
func (v *productionValidator) Validate(raw []byte) (result *ValidatedCandidate, gateErr *GateError) {
	// Defensive: candidate bytes must never be able to panic the watcher
	// (e.g. pre-existing nil-corner cases in copyToConfiguration).
	defer func() {
		if r := recover(); r != nil {
			gateErr = &GateError{Stage: GateFields, Err: fmt.Errorf("invalid configuration content: %v", r)}
		}
	}()

	parsed := &StorageDataplaneAPIConfiguration{}
	if err := yaml.Unmarshal(raw, parsed); err != nil {
		return nil, &GateError{Stage: GateYAML, Err: err}
	}

	probe := &Configuration{}
	probe.HAProxy = v.cli
	st := &StorageYML{}
	st.Set(parsed)
	probe.storage = st

	copyToConfiguration(probe)
	if err := validateReloadConfiguration(&probe.HAProxy); err != nil {
		return nil, &GateError{Stage: GateFields, Err: err}
	}

	listen, err := resolveListenSettings(parsed, v.server)
	if err != nil {
		return nil, &GateError{Stage: GateFields, Err: err}
	}
	if err := validateUsers(probe.Users); err != nil {
		return nil, &GateError{Stage: GateFields, Err: err}
	}
	if err := validateServiceDiscovery(parsed); err != nil {
		return nil, &GateError{Stage: GateFields, Err: err}
	}

	return &ValidatedCandidate{
		Fingerprint: fingerprint(raw),
		Raw:         raw,
		Parsed:      parsed,
		Effective:   probe.HAProxy,
		Listen:      listen,
		Users:       probe.Users,
	}, nil
}

// resolveListenSettings mirrors the YAML-to-server overlay performed by
// dataplaneapi.SyncWithFileSettings, including every HasOSArg CLI/env guard
// and the nil-scheme default of ["http"].
func resolveListenSettings(parsed *StorageDataplaneAPIConfiguration, baseline ServerSettings) (ListenSettings, error) {
	l := ListenSettings{
		Schemes:          append([]string(nil), baseline.EnabledListeners...),
		Host:             baseline.Host,
		Port:             baseline.Port,
		TLSHost:          baseline.TLSHost,
		TLSPort:          baseline.TLSPort,
		TLSCertificate:   baseline.TLSCertificate,
		TLSKey:           baseline.TLSKey,
		TLSCACertificate: baseline.TLSCACertificate,
		SocketPath:       flags.Filename(baseline.SocketPath),
	}
	d := parsed.Dataplaneapi
	if d == nil {
		if len(l.Schemes) == 0 {
			l.Schemes = []string{"http"}
		}
		return l, validateListenSettings(l)
	}

	if !misc.HasOSArg("", "scheme", "") {
		switch {
		case d.EnabledListeners != nil:
			l.Schemes = append([]string(nil), (*d.EnabledListeners)...)
		case len(l.Schemes) == 0:
			l.Schemes = []string{"http"}
		}
	}
	if d.SocketPath != nil && !misc.HasOSArg("", "socket-path", "") {
		l.SocketPath = *d.SocketPath
	}
	if d.Host != nil && !misc.HasOSArg("", "host", "HOST") {
		l.Host = *d.Host
	}
	if d.Port != nil && !misc.HasOSArg("", "port", "PORT") {
		l.Port = *d.Port
	}
	if d.TLS != nil {
		t := d.TLS
		if t.TLSHost != nil && !misc.HasOSArg("", "tls-host", "TLS_HOST") {
			l.TLSHost = *t.TLSHost
		}
		if t.TLSPort != nil && !misc.HasOSArg("", "tls-port", "TLS_PORT") {
			l.TLSPort = *t.TLSPort
		}
		if t.TLSCertificate != nil && !misc.HasOSArg("", "tls-certificate", "TLS_CERTIFICATE") {
			l.TLSCertificate = string(*t.TLSCertificate)
		}
		if t.TLSCertificateKey != nil && !misc.HasOSArg("", "tls-key", "TLS_PRIVATE_KEY") {
			l.TLSKey = string(*t.TLSCertificateKey)
		}
		if t.TLSCACertificate != nil && !misc.HasOSArg("", "tls-ca", "TLS_CA_CERTIFICATE") {
			l.TLSCACertificate = string(*t.TLSCACertificate)
		}
	}

	return l, validateListenSettings(l)
}

func validateListenSettings(l ListenSettings) error {
	for _, scheme := range l.Schemes {
		switch scheme {
		case schemeHTTP, schemeHTTPS, schemeUnix:
		default:
			return fmt.Errorf("invalid listener scheme %q", scheme)
		}
	}
	if l.Port < 0 || l.Port > 65535 {
		return fmt.Errorf("invalid port %d", l.Port)
	}
	if l.TLSPort < 0 || l.TLSPort > 65535 {
		return fmt.Errorf("invalid tls port %d", l.TLSPort)
	}
	if hasScheme(l.Schemes, schemeHTTPS) {
		if l.TLSCertificate == "" || l.TLSKey == "" {
			return errors.New("https listener requires tls_certificate and tls_key")
		}
	}
	return nil
}

func hasScheme(schemes []string, want string) bool {
	return slices.Contains(schemes, want)
}

// validateUsers covers only users embedded in the candidate YAML. The
// userlist-file / HAProxy-cfg source is verified by the dependency gate,
// mirroring Users.Init (configuration/user.go).
func validateUsers(users []User) error {
	seen := make(map[string]struct{}, len(users))
	for _, u := range users {
		if u.Name == "" {
			return errors.New("user entry with empty name")
		}
		if u.Password == "" {
			return fmt.Errorf("user %q has empty password", u.Name)
		}
		if _, dup := seen[u.Name]; dup {
			return fmt.Errorf("duplicate user %q", u.Name)
		}
		seen[u.Name] = struct{}{}
		if !u.Insecure && !acceptableStoredSecret(u.Password) {
			return fmt.Errorf("user %q password must be a hashed value ($1$/$5$/$6$ crypt) or a \"${ENV_VAR}\" reference", u.Name)
		}
	}
	return nil
}

// acceptableStoredSecret matches the shapes AuthenticateUser can verify:
// crypt hashes consumed by checkPassword, or "${ENV_VAR}" references.
func acceptableStoredSecret(pw string) bool {
	if strings.HasPrefix(pw, "\"${") && strings.HasSuffix(pw, "}\"") {
		return true
	}
	parts := strings.Split(pw, "$")
	if len(parts) != 4 {
		return false
	}
	switch parts[1] {
	case "1", "5", "6":
		return true
	default:
		return false
	}
}

// validateServiceDiscovery validates the deprecated in-YAML service
// discovery section with the same validators used at startup
// (configure_data_plane.go), assigning UUIDs to entries lacking one. It does
// not perform migration or touch the JSON storages.
func validateServiceDiscovery(parsed *StorageDataplaneAPIConfiguration) error {
	sd := parsed.DeprecatedServiceDiscovery
	if sd == nil {
		return nil
	}
	if sd.Consuls != nil {
		for _, data := range *sd.Consuls {
			if data.ID == nil || *data.ID == "" {
				data.ID = discovery.NewServiceDiscoveryUUID()
			}
			if err := discovery.ValidateConsulData(data, true); err != nil {
				return fmt.Errorf("invalid consul service discovery entry: %w", err)
			}
		}
	}
	if sd.AWSRegions != nil {
		for _, data := range *sd.AWSRegions {
			if data.ID == nil || *data.ID == "" {
				data.ID = discovery.NewServiceDiscoveryUUID()
			}
			if err := discovery.ValidateAWSData(data, true); err != nil {
				return fmt.Errorf("invalid aws service discovery entry: %w", err)
			}
		}
	}
	return nil
}
