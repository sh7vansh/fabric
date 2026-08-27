package wireguard

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"

	"fabric/internal/protocol"
)

// TCPBridge manages userspace TCP listeners on the virtual netstack to bridge incoming WireGuard connections.
type TCPBridge struct {
	engine    *WireGuardEngine
	listeners map[int]net.Listener
	mu        sync.RWMutex
	closed    bool
}

// newTCPBridge initializes a TCPBridge attached to the WireGuard engine's netstack.
func newTCPBridge(engine *WireGuardEngine) *TCPBridge {
	return &TCPBridge{
		engine:    engine,
		listeners: make(map[int]net.Listener),
	}
}

// StartCommonListeners binds listeners on common application ports (80, 443, 8080, 3000, 8000, 22, 5432, 9000).
func (b *TCPBridge) StartCommonListeners() {
	commonPorts := []int{22, 80, 443, 3000, 5432, 8000, 8080, 8443, 9000, 9090}
	for _, port := range commonPorts {
		_ = b.ListenPort(port)
	}
}

// ListenPort ensures a virtual TCP listener is actively serving on the specified port.
func (b *TCPBridge) ListenPort(port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return net.ErrClosed
	}

	if _, exists := b.listeners[port]; exists {
		return nil
	}

	ln, err := b.engine.tnet.ListenTCP(&net.TCPAddr{Port: port})
	if err != nil {
		return fmt.Errorf("failed to listen on virtual TCP port %d: %w", port, err)
	}

	b.listeners[port] = ln
	go b.serveListener(ln, port)
	return nil
}

// ListenPorts binds virtual TCP listeners on multiple specified ports.
func (b *TCPBridge) ListenPorts(ports ...int) error {
	for _, port := range ports {
		if err := b.ListenPort(port); err != nil {
			return err
		}
	}
	return nil
}

// ListenRange binds virtual TCP listeners across a contiguous range of ports [startPort, endPort].
func (b *TCPBridge) ListenRange(startPort, endPort int) error {
	if startPort <= 0 || endPort > 65535 || startPort > endPort {
		return fmt.Errorf("invalid port range %d-%d", startPort, endPort)
	}
	for port := startPort; port <= endPort; port++ {
		if err := b.ListenPort(port); err != nil {
			return err
		}
	}
	return nil
}

func (b *TCPBridge) serveListener(ln net.Listener, port int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			b.mu.RLock()
			closed := b.closed
			b.mu.RUnlock()
			if closed {
				return
			}
			return
		}

		go b.handleInboundStream(conn, port)
	}
}

func (b *TCPBridge) handleInboundStream(clientConn net.Conn, defaultPort int) {
	defer clientConn.Close()

	localAddr := clientConn.LocalAddr().String()
	host, portStr, err := net.SplitHostPort(localAddr)
	targetPort := defaultPort
	if err == nil {
		if p, pErr := strconv.Atoi(portStr); pErr == nil && p > 0 {
			targetPort = p
		}
	} else {
		host = localAddr
	}

	targetIP := net.ParseIP(host)
	if targetIP == nil {
		return
	}

	hostname, found := b.engine.ipam.LookupHostnameByIP(targetIP)
	if !found {
		if devName, devFound := b.engine.ipam.LookupDeviceByIP(targetIP); devFound {
			hostname = devName
			found = true
		}
	}
	if !found {
		return
	}

	if b.engine.proxyRouter == nil {
		return
	}

	req := protocol.ProxyRequest{
		Type:           protocol.TypeProxyRequest,
		TargetHostname: hostname,
		TargetHost:     "127.0.0.1",
		TargetPort:     targetPort,
	}

	envJSON, err := json.Marshal(req)
	if err != nil {
		log.Printf("[WireGuard/TCP] Failed to encode proxy envelope for %s:%d: %v\n", hostname, targetPort, err)
		return
	}

	if err := b.engine.proxyRouter.RouteProxyStream(hostname, envJSON, clientConn); err != nil {
		log.Printf("[WireGuard/TCP] Failed to route proxy stream to thread %s: %v\n", hostname, err)
	}
}

// Close closes all virtual TCP listeners.
func (b *TCPBridge) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}
	b.closed = true

	var firstErr error
	for port, ln := range b.listeners {
		if err := ln.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(b.listeners, port)
	}
	return firstErr
}
