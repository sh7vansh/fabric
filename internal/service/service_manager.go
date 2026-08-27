package service

import (
	"fmt"
	"sync"
)

// ServiceStatus represents the current runtime status of a service.
type ServiceStatus struct {
	Name    string
	Role    string
	Active  bool
	Running bool
	PID     int
	Details string
}

// ConfigEnv holds environment variables or configuration properties passed to service installer.
type ConfigEnv map[string]string

// ServiceManager defines the high-level service lifecycle management interface.
type ServiceManager interface {
	Install(role string, env ConfigEnv) error
	Uninstall(role string) error
	Start(role string) error
	Stop(role string) error
	Restart(role string) error
	Status(role string) (ServiceStatus, error)
	HandleAction(action, role string) error
}

// SystemdServiceAdapter implements ServiceManager using host systemd/supervisor via InitManager.
type SystemdServiceAdapter struct {
	initMgr *InitManager
}

// NewSystemdServiceAdapter creates a new live systemd/supervisor adapter.
func NewSystemdServiceAdapter() *SystemdServiceAdapter {
	return &SystemdServiceAdapter{
		initMgr: NewInitManager(),
	}
}

func (s *SystemdServiceAdapter) Install(role string, env ConfigEnv) error {
	return s.initMgr.InstallService(role)
}

func (s *SystemdServiceAdapter) Uninstall(role string) error {
	return s.initMgr.UninstallService(role)
}

func (s *SystemdServiceAdapter) Start(role string) error {
	return s.initMgr.HandleAction("start", role)
}

func (s *SystemdServiceAdapter) Stop(role string) error {
	return s.initMgr.HandleAction("stop", role)
}

func (s *SystemdServiceAdapter) Restart(role string) error {
	return s.initMgr.HandleAction("restart", role)
}

func (s *SystemdServiceAdapter) Status(role string) (ServiceStatus, error) {
	err := s.initMgr.HandleAction("status", role)
	return ServiceStatus{Role: role, Active: err == nil}, err
}

func (s *SystemdServiceAdapter) HandleAction(action, role string) error {
	return s.initMgr.HandleAction(action, role)
}

// MemoryServiceAdapter implements ServiceManager in-memory for rootless testing and dry-runs.
type MemoryServiceAdapter struct {
	mu           sync.Mutex
	Installed    map[string]bool
	InstalledEnv map[string]ConfigEnv
	Actions      []string
	Units        map[string]string
	State        map[string]string
}

// NewMemoryServiceAdapter creates an in-memory service adapter.
func NewMemoryServiceAdapter() *MemoryServiceAdapter {
	return &MemoryServiceAdapter{
		Installed:    make(map[string]bool),
		InstalledEnv: make(map[string]ConfigEnv),
		Units:        make(map[string]string),
		State:        make(map[string]string),
	}
}

func (m *MemoryServiceAdapter) Install(role string, env ConfigEnv) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Installed[role] = true
	m.InstalledEnv[role] = env
	m.State[role] = "active"
	m.Actions = append(m.Actions, fmt.Sprintf("install:%s", role))
	return nil
}

func (m *MemoryServiceAdapter) Uninstall(role string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.Installed, role)
	delete(m.InstalledEnv, role)
	delete(m.State, role)
	m.Actions = append(m.Actions, fmt.Sprintf("uninstall:%s", role))
	return nil
}

func (m *MemoryServiceAdapter) Start(role string) error {
	return m.HandleAction("start", role)
}

func (m *MemoryServiceAdapter) Stop(role string) error {
	return m.HandleAction("stop", role)
}

func (m *MemoryServiceAdapter) Restart(role string) error {
	return m.HandleAction("restart", role)
}

func (m *MemoryServiceAdapter) Status(role string) (ServiceStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.State[role]
	active := state == "active"
	return ServiceStatus{
		Name:    "fabric-" + role,
		Role:    role,
		Active:  active,
		Running: active,
		Details: state,
	}, nil
}

func (m *MemoryServiceAdapter) HandleAction(action, role string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Actions = append(m.Actions, fmt.Sprintf("%s:%s", action, role))
	switch action {
	case "start":
		m.State[role] = "active"
	case "stop":
		m.State[role] = "stopped"
	case "restart":
		m.State[role] = "active"
	}
	return nil
}
