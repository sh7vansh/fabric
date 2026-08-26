package server_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"fabric/internal/server"
)

func TestAccessControllerCapabilities(t *testing.T) {
	ac := server.NewAccessController(server.AccessControllerConfig{
		ClusterToken: "cluster-secret",
		AdminToken:   "admin-secret",
	})
	defer ac.Close()

	// 1. Register a scoped token with only inspect capability
	ac.RegisterScopedToken("telemetry-token", "telemetry-agent", []string{server.CapabilityInspect})

	// Test Admin token has all capabilities
	reqAdmin := httptest.NewRequest("GET", "/ws", nil)
	reqAdmin.Header.Set("Authorization", "Bearer admin-secret")
	ident, code, err := ac.AuthenticateRequest(reqAdmin, server.CapabilityAdmin, server.CapabilityExec)
	if err != nil || code != http.StatusOK {
		t.Fatalf("expected admin auth to succeed, got code %d, err %v", code, err)
	}
	if ident.Role != "admin" || !ident.HasCapability(server.CapabilityAdmin) || !ident.HasCapability(server.CapabilityExec) {
		t.Errorf("admin identity missing expected role or capabilities: %+v", ident)
	}

	// Test Cluster token has standard capabilities but not admin
	reqCluster := httptest.NewRequest("GET", "/ws", nil)
	reqCluster.Header.Set("Authorization", "Bearer cluster-secret")
	ident, code, err = ac.AuthenticateRequest(reqCluster, server.CapabilityInspect, server.CapabilityExec)
	if err != nil || code != http.StatusOK {
		t.Fatalf("expected cluster auth to succeed, got code %d, err %v", code, err)
	}
	if ident.HasCapability(server.CapabilityAdmin) {
		t.Errorf("cluster token should not have admin capability")
	}

	// Test Scoped token has inspect but fails exec
	reqScoped := httptest.NewRequest("GET", "/threads", nil)
	reqScoped.Header.Set("Authorization", "Bearer telemetry-token")
	ident, code, err = ac.AuthenticateRequest(reqScoped, server.CapabilityInspect)
	if err != nil || code != http.StatusOK {
		t.Fatalf("expected scoped inspect auth to succeed, got code %d, err %v", code, err)
	}

	// Attempting an action requiring exec with scoped token returns 403 Forbidden
	reqScopedExec := httptest.NewRequest("POST", "/exec", nil)
	reqScopedExec.Header.Set("Authorization", "Bearer telemetry-token")
	_, code, err = ac.AuthenticateRequest(reqScopedExec, server.CapabilityExec)
	if code != http.StatusForbidden || err == nil {
		t.Errorf("expected 403 Forbidden for missing exec capability, got code %d, err %v", code, err)
	}
}

func TestAccessControllerRateLimiting(t *testing.T) {
	ac := server.NewAccessController(server.AccessControllerConfig{
		ClusterToken:      "cluster-secret",
		MaxFailedAttempts: 3,
		RateLimitWindow:   1 * time.Second,
	})
	defer ac.Close()

	remoteIP := "192.168.1.100:12345"

	// 3 failed attempts should result in 401 Unauthorized
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/ws", nil)
		req.RemoteAddr = remoteIP
		req.Header.Set("Authorization", "Bearer bad-token")
		_, code, _ := ac.AuthenticateRequest(req)
		if code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401 Unauthorized, got %d", i+1, code)
		}
	}

	// 4th attempt from same IP should immediately return 429 Too Many Requests
	reqBlocked := httptest.NewRequest("GET", "/ws", nil)
	reqBlocked.RemoteAddr = remoteIP
	reqBlocked.Header.Set("Authorization", "Bearer bad-token")
	_, code, err := ac.AuthenticateRequest(reqBlocked)
	if code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests, got code %d, err: %v", code, err)
	}

	// Another IP is unaffected
	reqOther := httptest.NewRequest("GET", "/ws", nil)
	reqOther.RemoteAddr = "192.168.1.101:12345"
	reqOther.Header.Set("Authorization", "Bearer cluster-secret")
	_, codeOther, errOther := ac.AuthenticateRequest(reqOther)
	if codeOther != http.StatusOK || errOther != nil {
		t.Fatalf("expected other IP to succeed, got %d, err: %v", codeOther, errOther)
	}
}
