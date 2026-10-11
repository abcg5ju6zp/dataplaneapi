// Copyright 2026 HAProxy Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
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
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

// SourceFactory builds an EventSource watching the given config file.
type SourceFactory func(configPath string) (EventSource, error)

// EventSource collapses the raw fsnotify event stream for one file into
// cap-1 "dirty" signals. A burst of in-place writes, an atomic rename
// replacement and an editor delete+recreate all surface as a single signal;
// the coordinator re-reads the file itself and never trusts event payloads.
type EventSource interface {
	Dirty() <-chan struct{}
	Errors() <-chan error
	Close() error
}

type fsNotifySource struct {
	watcher    *fsnotify.Watcher
	dirty      chan struct{}
	errs       chan error
	configPath string
}

func newFSNotifySource(configPath string) (EventSource, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	// Watching the parent directory (same technique as the haproxy.cfg
	// watcher) survives in-place writes, rename replacements and
	// delete+recreate cycles without re-adding the inode.
	if err := watcher.Add(filepath.Dir(filepath.Clean(configPath))); err != nil {
		_ = watcher.Close()
		return nil, err
	}
	s := &fsNotifySource{
		watcher:    watcher,
		dirty:      make(chan struct{}, 1),
		errs:       make(chan error, 1),
		configPath: filepath.Clean(configPath),
	}
	go s.loop()
	return s, nil
}

func (s *fsNotifySource) loop() {
	for {
		select {
		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}
			if filepath.Clean(event.Name) != s.configPath {
				continue
			}
			// Chmod-only events are irrelevant; renameio temp files never
			// match the exact config path.
			if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) == 0 {
				continue
			}
			select {
			case s.dirty <- struct{}{}:
			default:
			}
		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			if err != nil {
				select {
				case s.errs <- err:
				default:
				}
			}
		}
	}
}

func (s *fsNotifySource) Dirty() <-chan struct{} { return s.dirty }
func (s *fsNotifySource) Errors() <-chan error   { return s.errs }
func (s *fsNotifySource) Close() error           { return s.watcher.Close() }
