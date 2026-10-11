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
	"crypto/sha256"
	"encoding/hex"
	"time"

	flags "github.com/jessevdk/go-flags"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
	schemeUnix  = "unix"

	// defaultDebounce is the quiet period after the last coalesced fsnotify
	// event before a stable candidate is evaluated. It is only overridable
	// through HotReloadParams (tests), never through user-facing flags.
	defaultDebounce = 500 * time.Millisecond
	// defaultWatchRetry bounds how fast a broken fsnotify watcher is rebuilt.
	defaultWatchRetry = time.Second

	hotReloadDirNamePattern = ".%s.hotreload"
	stateFileName           = "state.json"
	lockFileName            = ".lock"
	backupFileName          = "last-active.yaml"
	rejectedFilePrefix      = "rejected-"
	rejectedFileSuffix      = ".yaml"
	rejectedKeep            = 5
	hotReloadStateVer       = 1
	hotReloadFileMode       = 0o600
)

// Outcome is the distinct, observable result of one candidate evaluation.
// The three failure classes demanded by the hot-reload contract are kept
// separate: temporary file absence, invalid content (syntax or fields), and
// failed dependency precheck.
type Outcome string

const (
	OutcomeAccepted         Outcome = "accepted"
	OutcomeUnchanged        Outcome = "unchanged"
	OutcomeFileMissing      Outcome = "file_missing"
	OutcomeUnreadable       Outcome = "unreadable"
	OutcomeInvalidYAML      Outcome = "invalid_yaml"
	OutcomeInvalidFields    Outcome = "invalid_fields"
	OutcomeDependencyFailed Outcome = "dependency_failed"
	OutcomeSuperseded       Outcome = "superseded"
	OutcomeError            Outcome = "error"
)

// Candidate is a stable, fully read snapshot offered for validation.
type Candidate struct {
	Generation  uint64
	Fingerprint string
	Raw         []byte
}

// ObservedEvent is delivered to the optional observer after every evaluation
// transition. Duplicate failures for identical content are not re-delivered.
type ObservedEvent struct {
	At          time.Time
	Generation  uint64
	Fingerprint string
	Outcome     Outcome
	Detail      string
	Err         error
}

// Observer is the observability hook used by tests and structured logging.
type Observer func(ObservedEvent)

// ServerSettings is the immutable snapshot of the parsed API server right
// after CLI parsing and before cfg.Load(). It is the baseline the candidate
// YAML fields are merged onto, under the exact same CLI/env override guards
// that SyncWithFileSettings applies at boot.
type ServerSettings struct {
	EnabledListeners []string
	Host             string
	Port             int
	TLSHost          string
	TLSPort          int
	TLSCertificate   string
	TLSKey           string
	TLSCACertificate string
	SocketPath       string
}

// ListenSettings is the effective listener configuration after overlaying
// the candidate YAML on the CLI baseline.
type ListenSettings struct {
	Schemes          []string
	Host             string
	Port             int
	TLSHost          string
	TLSPort          int
	TLSCertificate   string
	TLSKey           string
	TLSCACertificate string
	SocketPath       flags.Filename
}

// HotReloadParams configures the hot-reload coordinator and startup
// reconciliation. Zero-value optional fields receive production defaults.
type HotReloadParams struct {
	// ConfigPath is the dataplaneapi.yaml location; it is the only path the
	// hot-reload ledger depends on, so recovery still works when the file's
	// content (including any configured storage directory) is corrupt.
	ConfigPath string

	// CLIBaseline is cfg.HAProxy as it stands right after parser.Parse().
	CLIBaseline    HAProxyConfiguration
	ServerBaseline ServerSettings

	Debounce           time.Duration
	WatchRetryInterval time.Duration

	Validator CandidateValidator
	Deps      DependencyChecker
	NewSource SourceFactory

	// Reload hands an accepted candidate to the active control plane. In
	// production it is cfg.Notify.Reload.Notify (the SIGHUP restart loop).
	Reload   func()
	Observer Observer
	Now      func() time.Time
}

func (p *HotReloadParams) applyDefaults() {
	if p.Debounce <= 0 {
		p.Debounce = defaultDebounce
	}
	if p.WatchRetryInterval <= 0 {
		p.WatchRetryInterval = defaultWatchRetry
	}
	if p.Validator == nil {
		p.Validator = NewProductionValidator(p.CLIBaseline, p.ServerBaseline)
	}
	if p.Deps == nil {
		p.Deps = NewProductionDependencyChecker()
	}
	if p.NewSource == nil {
		p.NewSource = newFSNotifySource
	}
	if p.Reload == nil {
		p.Reload = func() {}
	}
	if p.Observer == nil {
		p.Observer = func(ObservedEvent) {}
	}
	if p.Now == nil {
		p.Now = time.Now
	}
}

// fingerprint is the content identity (sha256 hex of the raw bytes).
func fingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// gateContext is a small helper letting production checks honor cancellation.
func ctxDone(ctx context.Context) bool {
	return ctx.Err() != nil
}
