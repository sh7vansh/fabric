package main

import (
	"log"
	"net/url"
	"time"

	"fabric/internal/pki"

	"github.com/gorilla/websocket"
)

// ConnectWithRetry attempts to dial the Socket with exponential backoff and TLS negotiation.
func ConnectWithRetry(u url.URL, token string, caCertPath string) *websocket.Conn {
	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	dialer := websocket.DefaultDialer
	if u.Scheme == "wss" {
		var err error
		dialer, err = pki.NewWSSDialer(caCertPath)
		if err != nil {
			log.Printf("[TLS] Warning: failed to configure TLS client pool: %v", err)
			dialer = websocket.DefaultDialer
		}
	}

	for {
		log.Printf("Attempting to connect to %s...", u.String())
		c, _, err := dialer.Dial(u.String(), nil)
		if err == nil {
			log.Println("Connection established.")
			
			// Setup keepalive Ping handler
			c.SetPingHandler(func(appData string) error {
				c.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(time.Second*10))
				return nil
			})
			
			return c
		}

		formattedErr := pki.FormatTLSError(err)
		log.Printf("Dial failed: %v. Retrying in %v...", formattedErr, backoff)
		time.Sleep(backoff)

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
