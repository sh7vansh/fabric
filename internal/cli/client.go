package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/websocket"
)

type Client struct {
	Config *Config
}

func NewClient(cfg *Config) *Client {
	return &Client{Config: cfg}
}

func (c *Client) DialWebSocket() (*websocket.Conn, error) {
	u, err := url.Parse(c.Config.Host)
	if err != nil {
		return nil, fmt.Errorf("invalid host url: %w", err)
	}

	header := http.Header{}
	header.Add("Authorization", "Bearer "+c.Config.Token)

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), header)
	if err != nil {
		return nil, fmt.Errorf("websocket dial: %w", err)
	}
	return conn, nil
}

// HTTP request helper for REST API calls
func (c *Client) DoHTTP(method, path string, body interface{}) (*http.Response, error) {
	u, err := url.Parse(c.Config.Host)
	if err != nil {
		return nil, err
	}
	
	// Convert ws:// to http:// and wss:// to https://
	scheme := "http"
	if u.Scheme == "wss" {
		scheme = "https"
	}
	u.Scheme = scheme
	u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(path, "/")

	req, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+c.Config.Token)

	return http.DefaultClient.Do(req)
}

// Helper to decode JSON response
func DecodeJSON(resp *http.Response, v interface{}) error {
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}
