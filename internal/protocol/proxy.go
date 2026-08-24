package protocol

import (
	"io"
	"net"
	"sync"
)

const TypeProxyRequest EnvelopeType = "proxy_request"

type ProxyRequest struct {
	Type           EnvelopeType `json:"type"`
	TargetHostname string       `json:"target_hostname,omitempty"`
	TargetPort     int          `json:"target_port,omitempty"`
}

func Proxy(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(a, b)
	}()
	go func() {
		defer wg.Done()
		io.Copy(b, a)
	}()
	wg.Wait()
}
