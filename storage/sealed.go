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
	"fmt"
	"time"

	jsoniter "github.com/json-iterator/go"
)

const (
	metaKey       = "_dapi_meta"
	metaVersion   = 2
	checksumAlgo  = "sha256"
	redactedValue = "***REDACTED***"
)

// envelopeMeta carries the monotonic generation and the content
// integrity checksum alongside the persisted object. It is stored under
// the "_dapi_meta" key so that legacy readers unmarshalling the file
// directly into the data structs simply ignore it.
type envelopeMeta struct {
	Version      int       `json:"version"`
	Generation   uint64    `json:"generation"`
	ChecksumAlgo string    `json:"checksum_algo"`
	Checksum     string    `json:"checksum"`
	UpdatedAt    time.Time `json:"updated_at"`
}

var fastJSON = jsoniter.ConfigFastest

// decodeGeneric decodes JSON into map/any while keeping numbers as raw
// literals (so int64 values cannot lose precision through float64).
func decodeGeneric(raw []byte) (map[string]any, error) {
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// canonicalPayload re-encodes the data content (excluding _dapi_meta)
// with encoding/json, which sorts object keys recursively. The result is
// a whitespace- and key-order-insensitive fingerprint of the content.
func canonicalPayload(raw []byte) ([]byte, error) {
	doc, err := decodeGeneric(raw)
	if err != nil {
		return nil, err
	}
	delete(doc, metaKey)
	return json.Marshal(doc)
}

func checksumSHA256(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// encodeGeneration renders data as an indented v2 envelope of the given
// generation. The envelope stays flat (data fields at the top level next
// to _dapi_meta), which keeps it readable for legacy clients. The
// checksum is computed over the canonical data content — the same
// computation verify performs on re-read.
func encodeGeneration[T any](data T, generation uint64) ([]byte, error) {
	dataBytes, err := fastJSON.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshalling generation %d: %w", generation, err)
	}
	doc, err := decodeGeneric(dataBytes)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing generation %d: %w", generation, err)
	}
	canonical, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing generation %d: %w", generation, err)
	}
	doc[metaKey] = envelopeMeta{
		Version:      metaVersion,
		Generation:   generation,
		ChecksumAlgo: checksumAlgo,
		Checksum:     checksumSHA256(canonical),
		UpdatedAt:    time.Now().UTC(),
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding generation %d: %w", generation, err)
	}
	return out, nil
}

// decodedGeneration is the result of reading one state file.
type decodedGeneration[T any] struct {
	data       T
	meta       *envelopeMeta
	generation uint64
}

// decodeGeneration parses one file's bytes. Legacy v1 content (valid JSON
// without _dapi_meta) decodes successfully with meta == nil; such content
// is accepted and upgraded to v2 on the next successful write.
func decodeGeneration[T any](raw []byte) (decodedGeneration[T], error) {
	var data T
	if err := fastJSON.Unmarshal(raw, &data); err != nil {
		return decodedGeneration[T]{}, err
	}
	var holder struct {
		DAPIMeta *envelopeMeta `json:"_dapi_meta"`
	}
	if err := fastJSON.Unmarshal(raw, &holder); err != nil {
		return decodedGeneration[T]{}, err
	}
	d := decodedGeneration[T]{data: data, meta: holder.DAPIMeta}
	if holder.DAPIMeta != nil {
		d.generation = holder.DAPIMeta.Generation
	}
	return d, nil
}

// verify checks the integrity checksum recorded in the envelope against
// the content of the same bytes. It returns an error for v2 envelopes
// whose checksum does not match; v1 content (no meta) is not checksummed.
func (d decodedGeneration[T]) verify(raw []byte) error {
	if d.meta == nil {
		return nil
	}
	m := d.meta
	if m.Version != metaVersion {
		return fmt.Errorf("unsupported envelope version %d", m.Version)
	}
	if m.ChecksumAlgo != "" && m.ChecksumAlgo != checksumAlgo {
		return fmt.Errorf("unsupported checksum algorithm %q", m.ChecksumAlgo)
	}
	canonical, err := canonicalPayload(raw)
	if err != nil {
		return fmt.Errorf("canonicalizing persisted content: %w", err)
	}
	if checksumSHA256(canonical) != m.Checksum {
		return fmt.Errorf("content checksum mismatch (generation %d)", m.Generation)
	}
	return nil
}
