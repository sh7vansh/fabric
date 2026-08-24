package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"fabric/internal/pki"

	"github.com/gorilla/websocket"
)

type Client struct {
	Config *Config
}

func NewClient(cfg *Config) *Client {
	return &Client{Config: cfg}
}

func (c *Client) caCertPath() string {
	if c != nil && c.Config != nil {
		return c.Config.CACert
	}
	return ""
}

func (c *Client) DialWebSocket() (*websocket.Conn, error) {
	u, err := pki.NormalizeURL(c.Config.Host)
	if err != nil {
		return nil, fmt.Errorf("invalid host url: %w", err)
	}

	header := http.Header{}
	header.Add("Authorization", "Bearer "+c.Config.Token)

	dialer := websocket.DefaultDialer
	if u.Scheme == "wss" {
		var err error
		dialer, err = pki.NewWSSDialer(c.caCertPath())
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
	}

	conn, _, err := dialer.Dial(u.String(), header)
	if err != nil {
		return nil, pki.FormatTLSError(fmt.Errorf("websocket dial (%s): %w", u.String(), err))
	}
	return conn, nil
}

// HTTP request helper for REST API calls
func (c *Client) DoHTTP(method, path string, body interface{}) (*http.Response, error) {
	u, err := pki.NormalizeURL(c.Config.Host)
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

	httpClient := http.DefaultClient
	if scheme == "https" {
		tlsCfg, err := pki.BuildClientTLSConfig(c.caCertPath())
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
			Timeout: 30 * time.Second,
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, pki.FormatTLSError(err)
	}
	return resp, nil
}

// Helper to decode JSON response
func DecodeJSON(resp *http.Response, v interface{}) error {
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}
