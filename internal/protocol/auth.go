package protocol

import "crypto/subtle"

// ValidateToken verifies that provided matches expected in constant time.
// It returns false immediately if expected is empty or provided is empty.
func ValidateToken(provided, expected string) bool {
	if len(provided) == 0 || len(expected) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}
