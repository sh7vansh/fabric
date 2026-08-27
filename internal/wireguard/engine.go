package wireguard

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// ProxyRouter abstracts routing of proxied TCP streams to target threads.
type ProxyRouter interface {
	RouteProxyStream(targetHostname string, envelope []byte, srcStream net.Conn) error
}

// EngineConfig holds configuration for the pure userspace WireGuard engine.
type EngineConfig struct {
	Port         int
	Subnet       string
	PrivateKey   string
	KeyPath      string
	DevicesPath  string
	MeshDomain   string
	EndpointHost string
}

// WireGuardEngine embeds a pure Go userspace WireGuard gateway backed by gVisor netstack.
type WireGuardEngine struct {
	cfg EngineConfig

	serverPrivKey string
	serverPubKey  string
	listenPort    int

	tunDev tun.Device
	tnet   *netstack.Net
	dev    *device.Device
	bind   conn.Bind

	ipam        *IPAMManager
	store       *DeviceStore
	dnsServer   *DNSServer
	tcpBridge   *TCPBridge
	proxyRouter ProxyRouter

	mu      sync.RWMutex
	closed  bool
	closeCh chan struct{}
}

// NewEngine initializes and starts the userspace WireGuard engine, IPAM, and in-memory DNS.
func NewEngine(cfg EngineConfig, ipam *IPAMManager, store *DeviceStore, proxyRouter ProxyRouter) (*WireGuardEngine, error) {
	if cfg.Subnet == "" {
		cfg.Subnet = "100.64.0.0/10"
	}
	if cfg.MeshDomain == "" {
		cfg.MeshDomain = "fabric.mesh"
	}
	if ipam == nil {
		var err error
		ipam, err = NewIPAMManager(cfg.Subnet)
		if err != nil {
			return nil, fmt.Errorf("failed to init IPAM: %w", err)
		}
	}
	if store == nil {
		var err error
		store, err = NewDeviceStore(cfg.DevicesPath)
		if err != nil {
			return nil, fmt.Errorf("failed to init DeviceStore: %w", err)
		}
	}

	// 1. Resolve / Load / Generate Server Private & Public Key
	privKey := cfg.PrivateKey
	if privKey == "" && cfg.KeyPath != "" {
		if data, err := os.ReadFile(cfg.KeyPath); err == nil {
			privKey = strings.TrimSpace(string(data))
		}
	}
	if privKey == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			defaultKeyPath := filepath.Join(home, ".fabric", "wireguard_server.key")
			if data, readErr := os.ReadFile(defaultKeyPath); readErr == nil {
				privKey = strings.TrimSpace(string(data))
			} else {
				newPriv, newPub, genErr := GenerateKeypair()
				if genErr == nil {
					privKey = newPriv
					_ = os.MkdirAll(filepath.Dir(defaultKeyPath), 0700)
					_ = os.WriteFile(defaultKeyPath, []byte(newPriv), 0600)
					log.Printf("[WireGuard] Generated new server keypair (Public Key: %s)\n", newPub)
				}
			}
		}
	}
	if privKey == "" {
		newPriv, _, err := GenerateKeypair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate WireGuard server keypair: %w", err)
		}
		privKey = newPriv
	}

	pubKey, err := PublicKeyFromPrivate(privKey)
	if err != nil {
		return nil, fmt.Errorf("invalid server WireGuard private key: %w", err)
	}

	// 2. Create NetTUN virtual device and Netstack
	serverIPStr := ipam.ServerIP().String()
	serverAddr, err := netip.ParseAddr(serverIPStr)
	if err != nil {
		return nil, fmt.Errorf("invalid server IP %s: %w", serverIPStr, err)
	}

	localAddresses := []netip.Addr{serverAddr}
	// Add full overlay IP range so netstack accepts traffic for all Threads and Devices (100.64.0.2 - 100.64.255.254)
	for octet3 := 0; octet3 <= 255; octet3++ {
		for octet4 := 1; octet4 <= 254; octet4++ {
			if octet3 == 0 && octet4 == 1 {
				continue // serverAddr already added
			}
			if addr, err := netip.ParseAddr(fmt.Sprintf("100.64.%d.%d", octet3, octet4)); err == nil {
				localAddresses = append(localAddresses, addr)
			}
		}
	}
	dnsServers := []netip.Addr{serverAddr}

	tunDev, tnet, err := netstack.CreateNetTUN(localAddresses, dnsServers, 1420)
	if err != nil {
		return nil, fmt.Errorf("failed to create NetTUN: %w", err)
	}

	// 3. Create WireGuard Userspace Device
	bind := conn.NewDefaultBind()
	logger := device.NewLogger(device.LogLevelError, "[WireGuard] ")
	wgDev := device.NewDevice(tunDev, bind, logger)

	privHex, err := KeyBase64ToHex(privKey)
	if err != nil {
		wgDev.Close()
		return nil, fmt.Errorf("failed to convert private key to hex: %w", err)
	}

	uapiConf := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", privHex, cfg.Port)
	if err := wgDev.IpcSet(uapiConf); err != nil {
		wgDev.Close()
		return nil, fmt.Errorf("failed to apply initial WireGuard UAPI config: %w", err)
	}

	if err := wgDev.Up(); err != nil {
		wgDev.Close()
		return nil, fmt.Errorf("failed to bring WireGuard device up: %w", err)
	}

	listenPort := cfg.Port
	if actualPort := getActualListenPort(wgDev); actualPort > 0 {
		listenPort = actualPort
	}

	// 4. Start in-memory DNS server on 100.64.0.1:53 inside netstack
	dnsUDPConn, err := tnet.ListenUDP(&net.UDPAddr{IP: ipam.ServerIP(), Port: 53})
	var dnsSrv *DNSServer
	if err == nil {
		dnsSrv, err = NewDNSServer(dnsUDPConn, ipam, cfg.MeshDomain)
		if err != nil {
			log.Printf("[WireGuard] Warning: Failed to start in-memory DNS server: %v\n", err)
		}
	} else {
		log.Printf("[WireGuard] Warning: Failed to bind virtual UDP port 53: %v\n", err)
	}

	engine := &WireGuardEngine{
		cfg:           cfg,
		serverPrivKey: privKey,
		serverPubKey:  pubKey,
		listenPort:    listenPort,
		tunDev:        tunDev,
		tnet:          tnet,
		dev:           wgDev,
		bind:          bind,
		ipam:          ipam,
		store:         store,
		dnsServer:     dnsSrv,
		proxyRouter:   proxyRouter,
		closeCh:       make(chan struct{}),
	}

	engine.tcpBridge = newTCPBridge(engine)
	engine.tcpBridge.StartCommonListeners()

	// 5. Restore persisted devices into IPAM and WireGuard device peers
	engine.restoreDevices()

	log.Printf("[WireGuard] Pure userspace WireGuard engine running on UDP :%d (Overlay IP: %s/10, Public Key: %s)\n",
		listenPort, serverIPStr, pubKey)

	return engine, nil
}

func getActualListenPort(dev *device.Device) int {
	ipc, err := dev.IpcGet()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(ipc, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			p, _ := strconv.Atoi(strings.TrimPrefix(line, "listen_port="))
			return p
		}
	}
	return 0
}

func (e *WireGuardEngine) restoreDevices() {
	devices := e.store.List()
	for _, dev := range devices {
		ip := net.ParseIP(dev.VirtualIP)
		if ip != nil {
			_ = e.ipam.ReserveDeviceIP(dev.Name, ip)
		}
		_ = e.addPeerToWireGuard(dev.PublicKey, dev.VirtualIP, dev.PresharedKey)
	}
}

func (e *WireGuardEngine) addPeerToWireGuard(pubKeyB64, virtualIP, pskB64 string) error {
	pubHex, err := KeyBase64ToHex(pubKeyB64)
	if err != nil {
		return err
	}

	uapi := fmt.Sprintf("public_key=%s\nallowed_ip=%s/32\npersistent_keepalive_interval=25\n", pubHex, virtualIP)
	if pskB64 != "" {
		if pskHex, err := KeyBase64ToHex(pskB64); err == nil {
			uapi += fmt.Sprintf("preshared_key=%s\n", pskHex)
		}
	}

	return e.dev.IpcSet(uapi)
}

func (e *WireGuardEngine) removePeerFromWireGuard(pubKeyB64 string) error {
	pubHex, err := KeyBase64ToHex(pubKeyB64)
	if err != nil {
		return err
	}
	uapi := fmt.Sprintf("public_key=%s\nremove=true\n", pubHex)
	return e.dev.IpcSet(uapi)
}

// ServerPublicKey returns the Base64 public key of the WireGuard gateway.
func (e *WireGuardEngine) ServerPublicKey() string {
	return e.serverPubKey
}

// ServerPrivateKey returns the Base64 private key of the WireGuard gateway.
func (e *WireGuardEngine) ServerPrivateKey() string {
	return e.serverPrivKey
}

// ListenPort returns the bound host UDP port.
func (e *WireGuardEngine) ListenPort() int {
	return e.listenPort
}

// IPAM returns the attached IPAM manager.
func (e *WireGuardEngine) IPAM() *IPAMManager {
	return e.ipam
}

// Store returns the attached DeviceStore.
func (e *WireGuardEngine) Store() *DeviceStore {
	return e.store
}

// Netstack returns the underlying virtual Netstack.
func (e *WireGuardEngine) Netstack() *netstack.Net {
	return e.tnet
}

// Bridge returns the attached TCPBridge.
func (e *WireGuardEngine) Bridge() *TCPBridge {
	return e.tcpBridge
}

// AddDevice pairs a new client device, allocates a virtual IP, and configures the WireGuard peer.
func (e *WireGuardEngine) AddDevice(name, pubKey string, psk ...string) (*DeviceEntry, error) {
	if name == "" {
		return nil, errors.New("device name is required")
	}
	if pubKey == "" {
		return nil, errors.New("device public key is required")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.store.Get(name); exists {
		return nil, ErrDeviceAlreadyExists
	}
	if _, exists := e.store.GetByPublicKey(pubKey); exists {
		return nil, ErrDevicePublicKeyUsed
	}

	ip, err := e.ipam.AllocateDeviceIP(name)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate device virtual IP: %w", err)
	}

	presharedKey := ""
	if len(psk) > 0 {
		presharedKey = psk[0]
	}

	entry := DeviceEntry{
		Name:         name,
		PublicKey:    pubKey,
		PresharedKey: presharedKey,
		VirtualIP:    ip.String(),
		AllowedIPs:   []string{ip.String() + "/32"},
		CreatedAt:    time.Now().UTC(),
	}

	if err := e.addPeerToWireGuard(pubKey, ip.String(), presharedKey); err != nil {
		e.ipam.ReleaseDeviceIP(name)
		return nil, fmt.Errorf("failed to configure WireGuard peer: %w", err)
	}

	if err := e.store.Add(entry); err != nil {
		_ = e.removePeerFromWireGuard(pubKey)
		e.ipam.ReleaseDeviceIP(name)
		return nil, fmt.Errorf("failed to persist device: %w", err)
	}

	return &entry, nil
}

// RemoveDevice revokes a client device key, removes the WireGuard peer, and reclaims its IP.
func (e *WireGuardEngine) RemoveDevice(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	dev, ok := e.store.Get(name)
	if !ok {
		return ErrDeviceNotFound
	}

	_ = e.removePeerFromWireGuard(dev.PublicKey)
	e.ipam.ReleaseDeviceIP(name)

	_, err := e.store.Delete(name)
	return err
}

// ListDevices returns all paired devices with live transfer stats from UAPI if available.
func (e *WireGuardEngine) ListDevices() []DeviceEntry {
	devices := e.store.List()
	stats := e.fetchPeerStats()

	for i := range devices {
		if s, ok := stats[devices[i].PublicKey]; ok {
			devices[i].RxBytes = s.RxBytes
			devices[i].TxBytes = s.TxBytes
			devices[i].LastHandshake = s.LastHandshake
			devices[i].Endpoint = s.Endpoint
		}
	}
	return devices
}

type peerStat struct {
	RxBytes       int64
	TxBytes       int64
	LastHandshake time.Time
	Endpoint      string
}

func (e *WireGuardEngine) fetchPeerStats() map[string]peerStat {
	stats := make(map[string]peerStat)
	ipc, err := e.dev.IpcGet()
	if err != nil {
		return stats
	}

	var currentPubB64 string
	var currentStat peerStat

	flushCurrent := func() {
		if currentPubB64 != "" {
			stats[currentPubB64] = currentStat
		}
	}

	for _, line := range strings.Split(ipc, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "public_key=") {
			flushCurrent()
			hexKey := strings.TrimPrefix(line, "public_key=")
			b64Key, _ := KeyHexToBase64(hexKey)
			currentPubB64 = b64Key
			currentStat = peerStat{}
		} else if strings.HasPrefix(line, "rx_bytes=") {
			v, _ := strconv.ParseInt(strings.TrimPrefix(line, "rx_bytes="), 10, 64)
			currentStat.RxBytes = v
		} else if strings.HasPrefix(line, "tx_bytes=") {
			v, _ := strconv.ParseInt(strings.TrimPrefix(line, "tx_bytes="), 10, 64)
			currentStat.TxBytes = v
		} else if strings.HasPrefix(line, "last_handshake_time_sec=") {
			sec, _ := strconv.ParseInt(strings.TrimPrefix(line, "last_handshake_time_sec="), 10, 64)
			if sec > 0 {
				currentStat.LastHandshake = time.Unix(sec, 0).UTC()
			}
		} else if strings.HasPrefix(line, "endpoint=") {
			currentStat.Endpoint = strings.TrimPrefix(line, "endpoint=")
		}
	}
	flushCurrent()
	return stats
}

// Close cleanly terminates the WireGuard device, DNS server, TCP bridge, and gVisor stack.
func (e *WireGuardEngine) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	close(e.closeCh)
	e.mu.Unlock()

	if e.tcpBridge != nil {
		_ = e.tcpBridge.Close()
	}
	if e.dnsServer != nil {
		_ = e.dnsServer.Close()
	}
	if e.dev != nil {
		e.dev.Close()
	} else if e.tunDev != nil {
		_ = e.tunDev.Close()
	}
	return nil
}
