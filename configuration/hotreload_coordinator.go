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
	"errors"
	"io/fs"
	"os"
	"strconv"
	"time"

	"github.com/haproxytech/dataplaneapi/log"
)

// HotReloadCoordinator is a single-goroutine state machine that coalesces
// file events into stable candidates, gates them through read -> parse ->
// field validation -> dependency precheck and only then hands them to the
// active control plane.
//
// All mutable state (active generation/fingerprint, epoch) is owned by the
// goroutine running Run; fsnotify delivers only collapsed dirty signals.
type HotReloadCoordinator struct {
	p     HotReloadParams
	store *stateStore

	activeGen         uint64
	activeFP          string
	rollbackAvailable bool
	lastRejected      *rejectedRecord

	// lastFailKey suppresses duplicate observability for identical bad content.
	lastFailKey string

	// epoch is bumped by every dirty signal; a validation result whose epoch
	// is stale is discarded as superseded and can never publish.
	epoch uint64
}

// NewHotReloadCoordinator performs the synchronous INIT phase: it creates
// the state directory, seeds or re-synchronizes the accepted-generation
// baseline and returns ready to run. A foreign or corrupt ledger, or an
// unreadable config file, yields an error (caller treats this as non-fatal).
func NewHotReloadCoordinator(params HotReloadParams) (*HotReloadCoordinator, error) {
	params.applyDefaults()
	c := &HotReloadCoordinator{
		p:     params,
		store: newStateStore(params.ConfigPath),
	}
	if err := c.bootstrap(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *HotReloadCoordinator) bootstrap() error {
	if err := c.store.ensureDir(); err != nil {
		return err
	}
	c.store.cleanupStaleTemp()

	raw, err := os.ReadFile(c.p.ConfigPath)
	if err != nil {
		if !isNotExist(err) || !c.store.exists() {
			return err
		}
		// File vanished since shutdown but a ledger+backup exist: restore.
		if restoreErr := c.store.withTransaction(func() error {
			return c.store.restoreBackupTo(c.p.ConfigPath)
		}); restoreErr != nil {
			return restoreErr
		}
		if raw, err = os.ReadFile(c.p.ConfigPath); err != nil {
			return err
		}
	}
	fp := fingerprint(raw)
	now := c.p.Now()

	if !c.store.exists() {
		// First time watching: current disk content seeds generation 1.
		st := hotReloadState{Generation: 1, Fingerprint: fp, ConfigPath: c.p.ConfigPath, AcceptedAt: now}
		if err := c.store.withTransaction(func() error {
			if err := c.store.writeBackup(raw); err != nil {
				return err
			}
			return c.store.commit(st)
		}); err != nil {
			return err
		}
		c.activeGen, c.activeFP, c.rollbackAvailable = 1, fp, true
		log.Infof("Hot-reload watcher seeded active generation 1 (%s)", shortFingerprint(fp))
		return nil
	}

	st, foreign, err := c.store.load()
	if err != nil {
		return err
	}
	if foreign {
		return errors.New("hot-reload state belongs to a different config file path; refusing to manage it")
	}

	switch fp {
	case st.Fingerprint:
		c.activeGen, c.activeFP = st.Generation, st.Fingerprint
		c.rollbackAvailable = c.store.backupExists()
		if !c.rollbackAvailable {
			log.Warningf("Hot-reload backup %s is missing; rollback unavailable until next accepted generation", c.store.backupPath())
		}
	default:
		// This iteration already loaded and is serving these bytes (own
		// cfg.Save normalization, or an edit in the save/start window):
		// resync without gates, keeping the same generation.
		resynced := *st
		resynced.Fingerprint = fp
		if err := c.store.withTransaction(func() error {
			if err := c.store.writeBackup(raw); err != nil {
				return err
			}
			return c.store.commit(resynced)
		}); err != nil {
			return err
		}
		c.activeGen, c.activeFP, c.rollbackAvailable = st.Generation, fp, true
		log.Infof("Hot-reload watcher re-synced active generation %d to current file content (%s)", st.Generation, shortFingerprint(fp))
	}
	return nil
}

type evalResult struct {
	epoch   uint64
	raw     []byte
	fp      string
	missing bool
	readErr error
	v       *ValidatedCandidate
	gate    *GateError
}

// runGates executes read -> idempotency short-circuit -> validate -> deps.
// It is safe to run on a worker goroutine: it touches no coordinator state
// other than the immutable active fingerprint passed in.
func (c *HotReloadCoordinator) runGates(ctx context.Context, epoch uint64, activeFP string) *evalResult {
	res := &evalResult{epoch: epoch}
	raw, err := os.ReadFile(c.p.ConfigPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			res.missing = true
		} else {
			res.readErr = err
		}
		return res
	}
	res.raw, res.fp = raw, fingerprint(raw)
	if res.fp == activeFP {
		return res // unchanged: skip parse/field/dependency gates entirely
	}
	v, gateErr := c.p.Validator.Validate(raw)
	if gateErr != nil {
		res.gate = gateErr
		return res
	}
	if gateErr = c.p.Deps.Check(ctx, v); gateErr != nil {
		res.gate = gateErr
		return res
	}
	res.v = v
	return res
}

func (c *HotReloadCoordinator) startEval(ctx context.Context, epoch uint64) <-chan *evalResult {
	ch := make(chan *evalResult, 1)
	go func() {
		ch <- c.runGates(ctx, epoch, c.activeFP)
	}()
	return ch
}

// apply commits or rejects one evaluation result. It runs on the coordinator
// goroutine, so promotions are serialized with the epoch bookkeeping.
func (c *HotReloadCoordinator) apply(ctx context.Context, res *evalResult) Outcome {
	switch {
	case res.missing:
		c.observe(0, "", OutcomeFileMissing, "config file temporarily absent; waiting for recovery", nil)
		return OutcomeFileMissing
	case res.readErr != nil:
		c.observe(0, "", OutcomeUnreadable, "cannot read config file; waiting", res.readErr)
		return OutcomeUnreadable
	case (res.fp == c.activeFP):
		c.observe(c.activeGen, res.fp, OutcomeUnchanged, "config content unchanged; ignoring write", nil)
		return OutcomeUnchanged
	case res.gate != nil:
		return c.applyFailure(res)
	default:
		return c.promote(res)
	}
}

func (c *HotReloadCoordinator) applyFailure(res *evalResult) Outcome {
	var (
		outcome Outcome
		detail  string
	)
	switch res.gate.Stage {
	case GateYAML:
		outcome, detail = OutcomeInvalidYAML, "invalid YAML syntax; active configuration unchanged; waiting for new content"
	case GateFields:
		outcome, detail = OutcomeInvalidFields, "invalid configuration fields; active configuration unchanged; waiting for new content"
	case GateDependency:
		return c.rollback(res)
	default:
		outcome, detail = OutcomeInvalidFields, res.gate.Error()
	}

	// Identical bad bytes repeatedly written produce one observable event.
	key := string(outcome) + "|" + res.fp
	if key != c.lastFailKey {
		c.lastFailKey = key
		c.observe(c.activeGen+1, res.fp, outcome, detail, res.gate.Err)
	}
	return outcome
}

// rollback handles dependency precheck failure: preserve the rejected
// candidate for inspection and atomically restore the last active generation
// to the config path. The restored file's own event converges to unchanged.
func (c *HotReloadCoordinator) rollback(res *evalResult) Outcome {
	candidateGen := c.activeGen + 1
	if record, err := c.store.saveRejected(candidateGen, res.raw, res.gate.Err.Error(), c.p.Now()); err != nil {
		log.Warningf("Hot-reload: failed to preserve rejected candidate: %s", err.Error())
	} else {
		c.lastRejected = record
	}

	if !c.rollbackAvailable {
		log.Errorf("Hot-reload: dependency precheck failed and no active backup exists; active configuration kept, manual intervention required: %s", res.gate.Err.Error())
		c.observe(candidateGen, res.fp, OutcomeDependencyFailed, "dependency precheck failed; rollback unavailable (no backup)", res.gate.Err)
		return OutcomeDependencyFailed
	}

	if err := c.store.withTransaction(func() error {
		return c.store.restoreBackupTo(c.p.ConfigPath)
	}); err != nil {
		c.observe(candidateGen, res.fp, OutcomeError, "dependency precheck failed and rollback restore failed", err)
		return OutcomeError
	}

	key := string(OutcomeDependencyFailed) + "|" + res.fp
	if key != c.lastFailKey {
		c.lastFailKey = key
		c.observe(candidateGen, res.fp, OutcomeDependencyFailed,
			"dependency precheck failed; rolled back to active generation "+strconv.FormatUint(c.activeGen, 10)+", rejected candidate preserved", res.gate.Err)
	}
	return OutcomeDependencyFailed
}

// promote persists the accepted candidate and hands it to the active control
// plane. Backup is written before the ledger commit; the reload notification
// is the very last step, so a lost callback or crash can never result in the
// same fingerprint restarting components twice.
func (c *HotReloadCoordinator) promote(res *evalResult) Outcome {
	newGen := c.activeGen + 1
	st := hotReloadState{
		Generation:   newGen,
		Fingerprint:  res.fp,
		ConfigPath:   c.p.ConfigPath,
		AcceptedAt:   c.p.Now(),
		LastRejected: c.lastRejected,
	}
	if err := c.store.withTransaction(func() error {
		if err := c.store.writeBackup(res.raw); err != nil {
			return err
		}
		return c.store.commit(st)
	}); err != nil {
		c.observe(newGen, res.fp, OutcomeError, "failed to persist accepted generation; active configuration unchanged", err)
		return OutcomeError
	}

	c.activeGen = newGen
	c.activeFP = res.fp
	c.rollbackAvailable = true
	c.lastFailKey = ""

	log.Infof("Hot-reload: candidate generation %d accepted (%s); activating via control plane reload", newGen, shortFingerprint(res.fp))
	c.p.Observer(ObservedEvent{
		At:          c.p.Now(),
		Generation:  newGen,
		Fingerprint: res.fp,
		Outcome:     OutcomeAccepted,
	})
	c.p.Reload()
	return OutcomeAccepted
}

func (c *HotReloadCoordinator) observe(generation uint64, fp string, outcome Outcome, detail string, err error) {
	c.p.Observer(ObservedEvent{
		At:          c.p.Now(),
		Generation:  generation,
		Fingerprint: fp,
		Outcome:     outcome,
		Detail:      detail,
		Err:         err,
	})
	switch outcome {
	case OutcomeAccepted:
		log.Infof("Hot-reload: %s", detail)
	case OutcomeUnchanged, OutcomeSuperseded:
		log.Debugf("Hot-reload: %s %v", detail, err)
	default:
		// file_missing, unreadable, invalid_yaml, invalid_fields,
		// dependency_failed and internal errors are operator-visible.
		log.Warningf("Hot-reload: %s %v", detail, err)
	}
}

// Run is the coordinator loop. It owns the debounce timer, the epoch guard
// and watcher re-establishment. Gate evaluation runs on a short-lived worker
// so that events arriving mid-evaluation are still observed and can supersede
// the in-flight result. Blocks until ctx is canceled.
func (c *HotReloadCoordinator) Run(ctx context.Context) {
	source := c.openSource(ctx)
	if source == nil {
		return
	}
	defer source.Close()

	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	arm := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(c.p.Debounce)
	}

	var (
		resultCh     <-chan *evalResult
		pendingEpoch uint64
	)

	for {
		select {
		case <-ctx.Done():
			return
		case <-source.Dirty():
			c.epoch++
			if resultCh == nil {
				arm() // trailing debounce: quiet period restarts at the last event
			}
		case err := <-source.Errors():
			log.Warningf("Hot-reload: file watcher error (%s); re-establishing watch", err.Error())
			source.Close()
			source = c.openSource(ctx)
			if source == nil {
				return
			}
			// Events may have been lost while the watcher was broken:
			// force an immediate re-evaluation.
			c.epoch++
			if resultCh == nil {
				timer.Stop()
				select {
				case <-timer.C:
				default:
				}
				timer.Reset(0)
			}
		case <-timer.C:
			if resultCh == nil {
				pendingEpoch = c.epoch
				resultCh = c.startEval(ctx, pendingEpoch)
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			}
		case res := <-resultCh:
			resultCh = nil
			if res.epoch != c.epoch {
				// Newer events arrived while this candidate was being
				// evaluated: the slower older result never publishes.
				log.Debugf("Hot-reload: discarding stale evaluation of generation %d (epoch %d != %d)", res.epoch+1, res.epoch, c.epoch)
				c.p.Observer(ObservedEvent{
					At:          c.p.Now(),
					Generation:  res.epoch + 1,
					Fingerprint: res.fp,
					Outcome:     OutcomeSuperseded,
				})
				arm()
				continue
			}
			applyEpoch := c.epoch
			c.apply(ctx, res)
			if c.epoch != applyEpoch {
				arm() // an event arrived during apply; re-evaluate newest
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			}
		}
	}
}

// openSource creates the watcher, retrying with the configured interval
// until success or ctx cancellation.
func (c *HotReloadCoordinator) openSource(ctx context.Context) EventSource {
	ticker := time.NewTicker(c.p.WatchRetryInterval)
	defer ticker.Stop()
	for {
		source, err := c.p.NewSource(c.p.ConfigPath)
		if err == nil {
			return source
		}
		log.Warningf("Hot-reload: failed to establish file watcher: %s", err.Error())
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// evaluateNow is a deterministic hook for tests: run one full gate cycle
// immediately, bypassing the debounce timer.
func (c *HotReloadCoordinator) evaluateNow(ctx context.Context) Outcome {
	res := c.runGates(ctx, c.epoch, c.activeFP)
	return c.apply(ctx, res)
}

func shortFingerprint(fp string) string {
	if len(fp) > 12 {
		return fp[:12]
	}
	return fp
}
