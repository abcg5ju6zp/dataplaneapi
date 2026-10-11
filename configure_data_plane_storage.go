package dataplaneapi

import (
	"os"
	"path/filepath"

	client_native "github.com/haproxytech/client-native/v6"
	native_misc "github.com/haproxytech/client-native/v6/misc"
	dataplaneapi_config "github.com/haproxytech/dataplaneapi/configuration"
	"github.com/haproxytech/dataplaneapi/log"
	dapi_storage "github.com/haproxytech/dataplaneapi/storage"
)

// storageStatus returns the current recovery conclusion of one internal
// state store. An unknown subsystem name is treated as Healthy.
func storageStatus(_ *dataplaneapi_config.Configuration, name string) dapi_storage.StatusReport {
	for _, r := range dataplaneapi_config.Get().StorageStatus() {
		if r.Name == name {
			return r
		}
	}
	return dapi_storage.StatusReport{Name: name, State: dapi_storage.Healthy}
}

func initDataplaneStorage(path string, client client_native.HAProxyClient) {
	if path == "" {
		return
	}
	if _, err := native_misc.CheckOrCreateWritableDirectory(path); err != nil {
		log.Fatalf("error initializing dataplane internal storage: %v", err)
	}
	if _, err := os.Stat(filepath.Join(path, "logs.json")); err != nil && os.IsNotExist(err) {
		generalStorage, storageErr := client.GeneralStorage()
		if storageErr != nil {
			log.Warningf("failed to get general storage: %v", storageErr)
			return
		}
		src, _, getErr := generalStorage.Get("logs.json")
		if getErr == nil {
			dst := filepath.Join(path, "logs.json")
			if err := os.Rename(src, dst); err != nil {
				log.Warningf("Failed to move logs.json to dataplane internal storage: %v", err)
			}
		}
	}
}
