package main

import (
	"log"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

// ConnectWithRetry attempts to dial the Socket with exponential backoff.
func ConnectWithRetry(u url.URL, token string) *websocket.Conn {
	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	for {
		log.Printf("Attempting to connect to %s...", u.String())
		c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
		if err == nil {
			log.Println("Connection established.")
			
			// Setup keepalive Ping handler
			c.SetPingHandler(func(appData string) error {
				c.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(time.Second*10))
				return nil
			})
			
			return c
		}

		log.Printf("Dial failed: %v. Retrying in %v...", err, backoff)
		time.Sleep(backoff)

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
