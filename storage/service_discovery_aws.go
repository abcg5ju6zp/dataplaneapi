package storage

import (
	"slices"
	"sync"

	"github.com/haproxytech/client-native/v6/models"
	"github.com/haproxytech/dataplaneapi/storagetype"
)

const (
	AWSRegionFileName = "service_discovery/aws.json"
)

type SDAWStorage interface {
	AWS

	Load() error
	Store() error
	Status() StatusReport
}

type AWS interface {
	// GetAWS does not load the AWSRegions from the storage. Use Load() to load the them if needed.
	GetAWSRegions() storagetype.AWSRegions
	// AddAWSRegionsAndStore adds a list of AWSRegions to the storage and stores in the storage file.
	AddAWSRegionsAndStore(AWS storagetype.AWSRegions) error
	// AddAWSRegionAndStore adds a new AWSRegion to the storage and stores in the storage file.
	AddAWSRegionAndStore(AWS *models.AwsRegion) error
	// RemoveAWSAndStore removes a AWSRegion from the storage and stores in the storage file.
	RemoveAWSRegionAndStore(AWS *models.AwsRegion) error
	// ReplaceAllAWSRegionsAndStore replaces the list of AWSRegions in the storage and stores in the storage file.
	ReplaceAllAWSRegionsAndStore(AWS storagetype.AWSRegions) error
}

type AWSRegionStorageImpl struct {
	AWSData storagetype.AWSRegionData
	storage Storage[storagetype.AWSRegionData]
	mu      sync.RWMutex
}

// NewSDAWSRegionStorage creates a new AWSRegionStorageImpl with initial configuration from a file path.
// It never fails on a corrupt state file: inspect Status for the independent
// recovery conclusion (recovered / read-only isolated / unavailable).
func NewSDAWSRegionStorage(path string) (SDAWStorage, error) {
	fs := newFileStorage[storagetype.AWSRegionData](path)
	AWSData, _ := fs.Get()
	return &AWSRegionStorageImpl{
		storage: fs,
		AWSData: AWSData,
	}, nil
}

func (cs *AWSRegionStorageImpl) Status() StatusReport {
	return cs.storage.Status()
}

func (cs *AWSRegionStorageImpl) GetAWSRegions() storagetype.AWSRegions {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.AWSData.AWSRegions
}

func (cs *AWSRegionStorageImpl) Load() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	aws, _ := cs.storage.Get()
	cs.AWSData = aws

	return nil
}

func (cs *AWSRegionStorageImpl) Store() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	return cs.commit(cs.AWSData.AWSRegions)
}

func (cs *AWSRegionStorageImpl) AddAWSRegionAndStore(region *models.AwsRegion) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	candidate := append(slices.Clone(cs.AWSData.AWSRegions), region)
	return cs.commit(candidate)
}

func (cs *AWSRegionStorageImpl) AddAWSRegionsAndStore(regions storagetype.AWSRegions) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	candidate := append(slices.Clone(cs.AWSData.AWSRegions), regions...)
	return cs.commit(candidate)
}

func (cs *AWSRegionStorageImpl) ReplaceAllAWSRegionsAndStore(regions storagetype.AWSRegions) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	return cs.commit(slices.Clone(regions))
}

func (cs *AWSRegionStorageImpl) RemoveAWSRegionAndStore(region *models.AwsRegion) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	candidate := make(storagetype.AWSRegions, 0, len(cs.AWSData.AWSRegions))
	for _, r := range cs.AWSData.AWSRegions {
		if r.Name != region.Name {
			candidate = append(candidate, r)
		}
	}
	return cs.commit(candidate)
}

// commit stores the candidate generation and swaps the in-memory active
// object only after the durable write is verified. On failure the active
// object converges with the engine's authoritative view (e.g. the
// restored last known good generation); a failed write never leaves a
// pending mutation visible.
func (cs *AWSRegionStorageImpl) commit(regions storagetype.AWSRegions) error {
	candidate := storagetype.AWSRegionData{AWSRegions: regions}
	if err := cs.storage.Store(candidate); err != nil {
		cs.AWSData = cs.storage.Active()
		return err
	}
	cs.AWSData = candidate
	return nil
}
