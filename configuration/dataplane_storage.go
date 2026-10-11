// Copyright 2019 HAProxy Technologies
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
	"path"

	"github.com/haproxytech/dataplaneapi/storage"
)

// loadClusterModeData loads dataplane-managed users from the dataplane storage
// file (and not from the dapi config file). A corrupt users state never
// aborts startup: the storage reports its own recovery conclusion.
func (c *Configuration) loadClusterModeData() error {
	clusterModeStorage, _ := storage.NewClusterModeStorage(path.Join(c.HAProxy.DataplaneStorageDir, storage.ClusterModeDataFileName))
	c.clusterModeStorage = clusterModeStorage

	return c.clusterModeStorage.Load()
}

func (c *Configuration) loadSDConsuls() error {
	consulStorage, _ := storage.NewSDConsulStorage(path.Join(c.HAProxy.DataplaneStorageDir, storage.ConsulFileName))
	if err := consulStorage.Load(); err != nil {
		return err
	}
	c.sdConsulStorage = consulStorage

	// Copy to configuration
	c.ServiceDiscovery.Consuls = c.sdConsulStorage.GetConsuls()

	return nil
}

// SaveSDConsuls persists the in-memory consuls. When the consul state is
// read-only isolated or unavailable the write is skipped (with no error)
// so that an isolated subsystem cannot take configuration saves down.
func (c *Configuration) SaveSDConsuls() error {
	if c.sdConsulStorage == nil {
		return nil
	}
	if !c.sdConsulStorage.Status().State.Writable() {
		return nil
	}
	err := c.sdConsulStorage.ReplaceAllConsulsAndStore(c.ServiceDiscovery.Consuls)
	if isDegradedStorageError(err) {
		return nil
	}
	return err
}

func (c *Configuration) loadSDAWSRegions() error {
	awsRegionStorage, _ := storage.NewSDAWSRegionStorage(path.Join(c.HAProxy.DataplaneStorageDir, storage.AWSRegionFileName))
	if err := awsRegionStorage.Load(); err != nil {
		return err
	}
	c.sdAWSRegionStorage = awsRegionStorage

	// Copy to configuration
	c.ServiceDiscovery.AWSRegions = c.sdAWSRegionStorage.GetAWSRegions()

	return nil
}

// SaveSDAWSRegions persists the in-memory AWS regions. Degraded states
// skip the write, mirroring SaveSDConsuls.
func (c *Configuration) SaveSDAWSRegions() error {
	if c.sdAWSRegionStorage == nil {
		return nil
	}
	if !c.sdAWSRegionStorage.Status().State.Writable() {
		return nil
	}
	err := c.sdAWSRegionStorage.ReplaceAllAWSRegionsAndStore(c.ServiceDiscovery.AWSRegions)
	if isDegradedStorageError(err) {
		return nil
	}
	return err
}

// StorageStatus returns the independent recovery conclusions of the three
// internal state stores. The reports never contain state contents or
// secrets.
func (c *Configuration) StorageStatus() []storage.StatusReport {
	reports := make([]storage.StatusReport, 0, 3)
	if c.clusterModeStorage != nil {
		reports = append(reports, c.clusterModeStorage.Status())
	}
	if c.sdConsulStorage != nil {
		reports = append(reports, c.sdConsulStorage.Status())
	}
	if c.sdAWSRegionStorage != nil {
		reports = append(reports, c.sdAWSRegionStorage.Status())
	}
	return reports
}

// storageWarning renders one human-readable, secret-free startup message
// for a non-healthy recovery conclusion. It returns "" for Healthy.
func storageWarning(r storage.StatusReport) string {
	switch r.State {
	case storage.Recovered:
		return fmt.Sprintf("[STORAGE RECOVERED] [%s] %s", r.Name, r.Detail)
	case storage.ReadOnlyIsolated:
		return fmt.Sprintf("[STORAGE READ-ONLY] [%s] %s; reads are served from the last known good generation, writes are rejected", r.Name, r.Detail)
	case storage.Unavailable:
		return fmt.Sprintf("[STORAGE UNAVAILABLE] [%s] %s; the dependent subsystem is isolated, the rest of the API keeps running", r.Name, r.Detail)
	default:
		return ""
	}
}

// isDegradedStorageError reports whether err is one of the storage
// sentinel errors describing a degraded write (reverted generation,
// read-only/unavailable store, stale generation or pre-commit failure).
func isDegradedStorageError(err error) bool {
	return errors.Is(err, storage.ErrWritePending) ||
		errors.Is(err, storage.ErrGenerationVerifyFailed) ||
		errors.Is(err, storage.ErrReadOnly) ||
		errors.Is(err, storage.ErrStorageUnavailable) ||
		errors.Is(err, storage.ErrStaleGeneration)
}
