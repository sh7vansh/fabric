package cli

import (
	"sync"

	"fabric/internal/service"
)

var (
	serviceMgrMu          sync.RWMutex
	defaultServiceManager service.ServiceManager
)

// SetServiceManager overrides the active ServiceManager implementation (primarily for rootless testing and dry-runs).
func SetServiceManager(mgr service.ServiceManager) {
	serviceMgrMu.Lock()
	defer serviceMgrMu.Unlock()
	defaultServiceManager = mgr
}

// GetServiceManager returns the active ServiceManager, defaulting to SystemdServiceAdapter.
func GetServiceManager() service.ServiceManager {
	serviceMgrMu.RLock()
	defer serviceMgrMu.RUnlock()
	if defaultServiceManager != nil {
		return defaultServiceManager
	}
	return service.NewSystemdServiceAdapter()
}
