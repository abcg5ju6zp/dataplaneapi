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
	"fmt"
	"os"
)

// ReconcileAction describes what startup reconciliation did.
type ReconcileAction string

const (
	ReconcileNone           ReconcileAction = "no_state"
	ReconcileForeign        ReconcileAction = "foreign_state"
	ReconcileAdoptedMatch   ReconcileAction = "adopted_match"
	ReconcileAdoptedDisk    ReconcileAction = "adopted_disk"
	ReconcileRestoredBackup ReconcileAction = "restored_backup"
)

// ReconcileResult reports the reconciliation outcome.
type ReconcileResult struct {
	Ran         bool
	Action      ReconcileAction
	Generation  uint64
	Fingerprint string
}

// ReconcileStartup runs BEFORE cfg.Load(). It reconciles the on-disk config
// file with the persisted last-accepted generation, covering crashes during
// candidate validation or active switching.
//
// When no ledger exists it is a pure no-op (a single stat): traditional
// startup behavior stays byte-for-byte identical and no files are created.
// Reconciliation runs regardless of --disable-inotify: the flag only
// controls whether a watcher is started, not boot-time safety.
func ReconcileStartup(params HotReloadParams) (ReconcileResult, error) {
	params.applyDefaults()
	store := newStateStore(params.ConfigPath)

	if !store.exists() {
		return ReconcileResult{Ran: false, Action: ReconcileNone}, nil
	}

	st, foreign, err := store.load()
	if err != nil {
		return ReconcileResult{Ran: true, Action: ReconcileNone}, err
	}
	if foreign {
		fmt.Printf("hot-reload state in %s was recorded for a different config file, ignoring it\n", store.dir)
		return ReconcileResult{Ran: false, Action: ReconcileForeign}, nil
	}

	raw, err := os.ReadFile(params.ConfigPath)
	switch {
	case err != nil && isNotExist(err):
		// File vanished since last run (crash during an editor delete window).
		if err := store.withTransaction(func() error {
			return store.restoreBackupTo(params.ConfigPath)
		}); err != nil {
			return ReconcileResult{Ran: true, Action: ReconcileNone},
				fmt.Errorf("hot-reload: config file %s is missing and restoring the last active generation failed: %w", params.ConfigPath, err)
		}
		fmt.Printf("hot-reload: config file %s was missing, restored last active generation %d\n", params.ConfigPath, st.Generation)
		return ReconcileResult{Ran: true, Action: ReconcileRestoredBackup, Generation: st.Generation, Fingerprint: st.Fingerprint}, nil
	case err != nil:
		return ReconcileResult{Ran: true, Action: ReconcileNone},
			fmt.Errorf("hot-reload: cannot read config file %s: %w", params.ConfigPath, err)
	}

	fp := fingerprint(raw)
	if fp == st.Fingerprint {
		return ReconcileResult{Ran: true, Action: ReconcileAdoptedMatch, Generation: st.Generation, Fingerprint: fp}, nil
	}

	// Disk differs from the ledger: a candidate may have been written while
	// the process was dying. Run the same gates the watcher runs. Adoption
	// requires the same guarantees as a live activation.
	v, gateErr := params.Validator.Validate(raw)
	if gateErr == nil {
		gateErr = params.Deps.Check(context.Background(), v)
	}
	if gateErr == nil {
		newGen := st.Generation + 1
		newState := *st
		newState.Generation = newGen
		newState.Fingerprint = fp
		if err := store.withTransaction(func() error {
			if err := store.writeBackup(raw); err != nil {
				return err
			}
			return store.commit(newState)
		}); err != nil {
			return ReconcileResult{Ran: true, Action: ReconcileNone}, err
		}
		fmt.Printf("hot-reload: on-disk config passed validation, adopted as generation %d\n", newGen)
		return ReconcileResult{Ran: true, Action: ReconcileAdoptedDisk, Generation: newGen, Fingerprint: fp}, nil
	}

	// Disk content never passed validation: it must never become active.
	if _, backupErr := store.readBackup(); backupErr != nil {
		return ReconcileResult{Ran: true, Action: ReconcileNone},
			fmt.Errorf("hot-reload: config file %s does not match the last accepted generation and is invalid (%s), and the active backup is unreadable: %w; refusing to start unvalidated content",
				params.ConfigPath, gateErr.Error(), backupErr)
	}
	if err := store.withTransaction(func() error {
		return store.restoreBackupTo(params.ConfigPath)
	}); err != nil {
		return ReconcileResult{Ran: true, Action: ReconcileNone}, err
	}
	fmt.Printf("hot-reload: on-disk config was invalid at startup (%s); restored last active generation %d\n", gateErr.Error(), st.Generation)
	return ReconcileResult{Ran: true, Action: ReconcileRestoredBackup, Generation: st.Generation, Fingerprint: st.Fingerprint}, nil
}
