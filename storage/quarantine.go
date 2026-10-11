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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"time"
)

const quarantineDirSuffix = ".quarantine"

// quarantineStage tells when the corruption was observed.
type quarantineStage string

const (
	stageStartup      quarantineStage = "startup"
	stageCommitVerify quarantineStage = "commit-verify"
)

// quarantineRecord is the only thing ever written next to a corrupt
// sample. It contains metadata plus — when the sample still parses as
// JSON — a recursively redacted copy. Raw corrupt bytes are never copied,
// so truncated files carrying passwords, tokens or keys cannot leak
// through diagnostics.
type quarantineRecord struct {
	OccurredAt      time.Time       `json:"occurred_at"`
	File            string          `json:"file"`
	Stage           quarantineStage `json:"stage"`
	Size            int64           `json:"size"`
	SHA256          string          `json:"sha256"`
	Error           string          `json:"error"`
	MainGeneration  uint64          `json:"main_generation,omitempty"`
	LKGGeneration   uint64          `json:"lkg_generation,omitempty"`
	RedactedContent json.RawMessage `json:"redacted_content,omitempty"`
}

// isSecretKey reports whether a JSON key names a credential. Matching is
// case-insensitive and intentionally defensive: anything containing
// "secret" or matching known credential names is redacted.
func isSecretKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	switch k {
	case "password", "passwd", "token", "authorization", "api_key", "apikey", "access_key_id", "secret_access_key":
		return true
	}
	return strings.Contains(k, "secret") || strings.Contains(k, "password")
}

// redactSecrets walks decoded JSON and replaces every scalar value found
// under a credential-like key with a marker. Maps and arrays are recursed
// into so users[], consuls[] and aws_regions[] are all covered.
func redactSecrets(v any) any {
	switch node := v.(type) {
	case map[string]any:
		for key, val := range node {
			if isSecretKey(key) {
				node[key] = redactedValue
				continue
			}
			node[key] = redactSecrets(val)
		}
		return node
	case []any:
		for i := range node {
			node[i] = redactSecrets(node[i])
		}
		return node
	default:
		return v
	}
}

// writeQuarantineRecord persists one safe diagnostic next to the active
// state file (<main>.quarantine/, mode 0700; sample files mode 0600).
func writeQuarantineRecord(mainPath string, stage quarantineStage, corrupt []byte, cause error, mainGen, lkgGen uint64) error {
	dir := mainPath + quarantineDirSuffix
	if err := mkdirPrivate(dir); err != nil {
		return err
	}

	sum := sha256.Sum256(corrupt)
	rec := quarantineRecord{
		OccurredAt:     time.Now().UTC(),
		File:           filepath.Base(mainPath),
		Stage:          stage,
		Size:           int64(len(corrupt)),
		SHA256:         hex.EncodeToString(sum[:]),
		Error:          cause.Error(),
		MainGeneration: mainGen,
		LKGGeneration:  lkgGen,
	}

	// Only attach content when the whole sample still parses: partial
	// JSON cannot be redacted reliably, so unparseable bytes are never
	// copied anywhere.
	dec := json.NewDecoder(bytes.NewReader(corrupt))
	dec.UseNumber()
	var parsed any
	if err := dec.Decode(&parsed); err == nil {
		if redacted, err := json.Marshal(redactSecrets(parsed)); err == nil {
			rec.RedactedContent = redacted
		}
	}

	out, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	name := "corrupt-" + rec.OccurredAt.Format("20060102T150405.000000") + "-" + rec.SHA256[:8] + ".json"
	return writeFilePrivate(filepath.Join(dir, name), out)
}
