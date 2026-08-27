package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// GenerateKeypair generates a new WireGuard Curve25519 private and public keypair (Base64 encoded).
func GenerateKeypair() (privateKeyBase64, publicKeyBase64 string, err error) {
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Clamp per RFC 7748 / WireGuard specification
	privateKey[0] &= 248
	privateKey[31] = (privateKey[31] & 127) | 64

	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	privB64 := base64.StdEncoding.EncodeToString(privateKey[:])
	pubB64 := base64.StdEncoding.EncodeToString(publicKey[:])
	return privB64, pubB64, nil
}

// GeneratePresharedKey generates a 32-byte symmetric preshared key (Base64 encoded).
func GeneratePresharedKey() (string, error) {
	var psk [32]byte
	if _, err := rand.Read(psk[:]); err != nil {
		return "", fmt.Errorf("failed to generate preshared key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(psk[:]), nil
}

// PublicKeyFromPrivate derives the WireGuard public key from a Base64 encoded private key.
func PublicKeyFromPrivate(privB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return "", fmt.Errorf("invalid base64 private key: %w", err)
	}
	if len(raw) != 32 {
		return "", errors.New("private key must be exactly 32 bytes")
	}

	var privateKey [32]byte
	copy(privateKey[:], raw)

	// Clamp
	privateKey[0] &= 248
	privateKey[31] = (privateKey[31] & 127) | 64

	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return base64.StdEncoding.EncodeToString(publicKey[:]), nil
}

// KeyBase64ToHex converts a Base64-encoded WireGuard key into standard lowercase Hex (64 chars) for UAPI.
func KeyBase64ToHex(keyB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", errors.New("key must be 32 bytes")
	}
	return hex.EncodeToString(raw), nil
}

// KeyHexToBase64 converts a Hex-encoded WireGuard key into standard Base64.
func KeyHexToBase64(keyHex string) (string, error) {
	raw, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", errors.New("key must be 32 bytes")
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}
