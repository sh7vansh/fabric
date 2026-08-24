package protocol

import "testing"

func TestValidateToken(t *testing.T) {
	tests := []struct {
		name     string
		provided string
		expected string
		want     bool
	}{
		{"matching tokens", "secret-token-123", "secret-token-123", true},
		{"mismatched tokens", "wrong-token", "secret-token-123", false},
		{"empty provided", "", "secret-token-123", false},
		{"empty expected", "secret-token-123", "", false},
		{"both empty", "", "", false},
		{"different length", "secret", "secret-123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateToken(tt.provided, tt.expected)
			if got != tt.want {
				t.Errorf("ValidateToken(%q, %q) = %v, want %v", tt.provided, tt.expected, got, tt.want)
			}
		})
	}
}
