package metafiles

import (
	"runtime"
	"sync"

	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/utils/env"
)

type StorageType int

const (
	InMemory StorageType = iota
	Hybrid
)

var (
	MaxHostsEntires = 4096
	// LoadAllEntries is a switch when true loads all entries to hybrid storage
	// backend and uses it even if in-memory storage backend was requested
	LoadAllEntries = false
)

func init() {
	MaxHostsEntires = env.GetEnvOrDefault("HF_MAX_HOSTS", 4096)
	LoadAllEntries = env.GetEnvOrDefault("HF_LOAD_ALL", false)
}

// GetHostsFileDnsData returns the immutable dns data that is constant throughout the program
// lifecycle and shouldn't be purged by cache etc.
func GetHostsFileDnsData(storage StorageType) (*hybrid.HybridMap, error) {
	if LoadAllEntries {
		storage = Hybrid
	}
	switch storage {
	case InMemory:
		return getHFInMemory()
	case Hybrid:
		return getHFHybridStorage()
	}
	return nil, nil
}

var hostsMemOnce = &sync.Once{}

// getImm
func getHFInMemory() (*hybrid.HybridMap, error) {
	var hm *hybrid.HybridMap
	var err error
	hostsMemOnce.Do(func() {
		opts := hybrid.DefaultMemoryOptions
		hm, err = hybrid.New(opts)
		if err != nil {
			return
		}
		err = loadHostsFile(hm, MaxHostsEntires)
		if err != nil {
			hm.Close()
			return
		}
	})
	return hm, nil
}

var hostsHybridOnce = &sync.Once{}

func getHFHybridStorage() (*hybrid.HybridMap, error) {
	var hm *hybrid.HybridMap
	var err error
	hostsHybridOnce.Do(func() {
		opts := hybrid.DefaultHybridOptions
		opts.Cleanup = true
		hm, err = hybrid.New(opts)
		if err != nil {
			return
		}
		err = loadHostsFile(hm, -1)
		if err != nil {
			hm.Close()
			return
		}
		// set finalizer for cleanup
		runtime.SetFinalizer(hm, func(hm *hybrid.HybridMap) {
			_ = hm.Close()
		})
	})
	return hm, nil
}
