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
	"fmt"
	"path"

	"github.com/haproxytech/dataplaneapi/storage"
	"github.com/haproxytech/dataplaneapi/storagetype"
)

// migrateDeprecatedFields moves Consul/AWS definitions still living in the
// YAML configuration file into the dedicated state files. It reports, per
// subsystem, whether the deprecated YAML section is safe to remove: when a
// state store is isolated or a write cannot be committed, its YAML section
// is intentionally preserved so credentials are never silently lost.
func (c *Configuration) migrateDeprecatedFields() ([]string, error) {
	deprecationInfoMsg := make([]string, 0)

	consulsMigrated, msgs, err := c.migrateSDConsuls()
	deprecationInfoMsg = append(deprecationInfoMsg, msgs...)
	if err != nil {
		return deprecationInfoMsg, err
	}

	awsMigrated, msgs, err := c.migrateSDAwsRegions()
	deprecationInfoMsg = append(deprecationInfoMsg, msgs...)
	if err != nil {
		return deprecationInfoMsg, err
	}

	c.storage.Get().emptyMigratedSections(consulsMigrated, awsMigrated)

	return deprecationInfoMsg, nil
}

func (c *Configuration) migrateSDConsuls() (bool, []string, error) {
	deprecationInfoMsg := make([]string, 0)

	dapiCfgStorage := c.storage.Get()
	dapiStorageConsuls := c.sdConsulStorage.GetConsuls()
	consulsStoragePath := path.Join(c.HAProxy.DataplaneStorageDir, storage.ConsulFileName)

	if dapiCfgStorage.DeprecatedServiceDiscovery == nil || dapiCfgStorage.DeprecatedServiceDiscovery.Consuls == nil {
		// Nothing to preserve in the YAML for this subsystem.
		return true, deprecationInfoMsg, nil
	}

	consulsToMigrate := make(storagetype.Consuls, 0)
	for _, cfgConsul := range *dapiCfgStorage.DeprecatedServiceDiscovery.Consuls {
		found := false
		// Check done on ID
		for _, dapiStorageConsul := range dapiStorageConsuls {
			if dapiStorageConsul.ID != nil && cfgConsul.ID != nil &&
				*dapiStorageConsul.ID == *cfgConsul.ID {
				found = true
				break
			}
		}

		consulID := ""
		if cfgConsul.ID != nil {
			consulID = *cfgConsul.ID
		}
		// Already migrated
		if found {
			msg := fmt.Sprintf("[CFG DEPRECATED] [SKIP] [Consul] [%s]: already migrated. Old location [%s] New location [%s]. Use only new location",
				consulID,
				c.HAProxy.DataplaneConfig,
				consulsStoragePath)
			// Logging is not done here as at startup, the logger is not yet initialized
			// so it's done later on
			deprecationInfoMsg = append(deprecationInfoMsg, msg)
		} else {
			// If not already migrated, then migrate it
			msg := fmt.Sprintf("[CFG DEPRECATED] [MIGRATE] [Consul] [%s]: migrating. Old location [%s] New location [%s]. Use only new location",
				consulID,
				c.HAProxy.DataplaneConfig,
				consulsStoragePath)
			// Logging is not done here as at startup, the logger is not yet initialized
			// so it's done later on
			deprecationInfoMsg = append(deprecationInfoMsg, msg)
			consulsToMigrate = append(consulsToMigrate, cfgConsul)
		}
	}
	if len(consulsToMigrate) > 0 && !c.sdConsulStorage.Status().State.Writable() {
		deprecationInfoMsg = append(deprecationInfoMsg,
			fmt.Sprintf("[CFG DEPRECATED] [SKIP] [Consul]: consul state is %s, %d definition(s) remain in %s and will be retried on next start",
				c.sdConsulStorage.Status().State, len(consulsToMigrate), c.HAProxy.DataplaneConfig))
		return false, deprecationInfoMsg, nil
	}
	if err := c.sdConsulStorage.AddConsulsAndStore(consulsToMigrate); err != nil {
		if isDegradedStorageError(err) {
			deprecationInfoMsg = append(deprecationInfoMsg,
				fmt.Sprintf("[CFG DEPRECATED] [SKIP] [Consul]: migration write was not committed (%v); definitions remain in %s and will be retried on next start",
					err, c.HAProxy.DataplaneConfig))
			return false, deprecationInfoMsg, nil
		}
		return false, deprecationInfoMsg, err
	}
	c.ServiceDiscovery.Consuls = append(c.ServiceDiscovery.Consuls, consulsToMigrate...)
	return true, deprecationInfoMsg, nil
}

func (c *Configuration) migrateSDAwsRegions() (bool, []string, error) {
	deprecationInfoMsg := make([]string, 0)

	dapiCfgStorage := c.storage.Get()
	dapiStorageAwsRegions := c.sdAWSRegionStorage.GetAWSRegions()
	awsRegionsStoragePath := path.Join(c.HAProxy.DataplaneStorageDir, storage.AWSRegionFileName)

	if dapiCfgStorage.DeprecatedServiceDiscovery == nil || dapiCfgStorage.DeprecatedServiceDiscovery.AWSRegions == nil {
		return true, deprecationInfoMsg, nil
	}

	awsRegionsToMigrate := make(storagetype.AWSRegions, 0)
	for _, cfgAwsRegion := range *dapiCfgStorage.DeprecatedServiceDiscovery.AWSRegions {
		found := false
		for _, dapiStorageAwsRegion := range dapiStorageAwsRegions {
			if dapiStorageAwsRegion.Name != nil && cfgAwsRegion.Name != nil &&
				*dapiStorageAwsRegion.Name == *cfgAwsRegion.Name {
				found = true
				break
			}
		}

		awsRegionName := ""
		if cfgAwsRegion.Name != nil {
			awsRegionName = *cfgAwsRegion.Name
		}
		// Already migrated
		if found {
			msg := fmt.Sprintf("[CFG DEPRECATED] [SKIP] [AWS Region] [%s]: already migrated. Old location [%s] New location [%s]. Use only new location",
				awsRegionName,
				c.HAProxy.DataplaneConfig,
				awsRegionsStoragePath)
			// Logging is not done here as at startup, the logger is not yet initialized
			// so it's done later on
			deprecationInfoMsg = append(deprecationInfoMsg, msg)
		} else {
			// If not already migrated, then migrate it
			msg := fmt.Sprintf("[CFG DEPRECATED] [MIGRATE] [AWS Region] [%s]: migrating. Old location [%s] New location [%s]. Use only new location",
				awsRegionName,
				c.HAProxy.DataplaneConfig,
				awsRegionsStoragePath)
			// Logging is not done here as at startup, the logger is not yet initialized
			// so it's done later on
			deprecationInfoMsg = append(deprecationInfoMsg, msg)
			awsRegionsToMigrate = append(awsRegionsToMigrate, cfgAwsRegion)
		}
	}
	if len(awsRegionsToMigrate) > 0 && !c.sdAWSRegionStorage.Status().State.Writable() {
		deprecationInfoMsg = append(deprecationInfoMsg,
			fmt.Sprintf("[CFG DEPRECATED] [SKIP] [AWS Region]: aws state is %s, %d definition(s) remain in %s and will be retried on next start",
				c.sdAWSRegionStorage.Status().State, len(awsRegionsToMigrate), c.HAProxy.DataplaneConfig))
		return false, deprecationInfoMsg, nil
	}
	if err := c.sdAWSRegionStorage.AddAWSRegionsAndStore(awsRegionsToMigrate); err != nil {
		if isDegradedStorageError(err) {
			deprecationInfoMsg = append(deprecationInfoMsg,
				fmt.Sprintf("[CFG DEPRECATED] [SKIP] [AWS Region]: migration write was not committed (%v); definitions remain in %s and will be retried on next start",
					err, c.HAProxy.DataplaneConfig))
			return false, deprecationInfoMsg, nil
		}
		return false, deprecationInfoMsg, err
	}
	c.ServiceDiscovery.AWSRegions = append(c.ServiceDiscovery.AWSRegions, awsRegionsToMigrate...)
	return true, deprecationInfoMsg, nil
}
