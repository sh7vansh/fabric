package wireguard

import (
	"testing"
)

func TestWireGuardKeyGeneration(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	if len(priv) != 44 || len(pub) != 44 {
		t.Errorf("expected 44-char base64 keys, got priv=%d, pub=%d", len(priv), len(pub))
	}

	derivedPub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate failed: %v", err)
	}
	if derivedPub != pub {
		t.Errorf("derived public key mismatch: %s != %s", derivedPub, pub)
	}

	// Hex conversion
	hexPub, err := KeyBase64ToHex(pub)
	if err != nil {
		t.Fatalf("KeyBase64ToHex failed: %v", err)
	}
	if len(hexPub) != 64 {
		t.Errorf("expected 64-char hex key, got %d", len(hexPub))
	}

	backPub, err := KeyHexToBase64(hexPub)
	if err != nil {
		t.Fatalf("KeyHexToBase64 failed: %v", err)
	}
	if backPub != pub {
		t.Errorf("hex roundtrip mismatch: %s != %s", backPub, pub)
	}

	// PSK
	psk, err := GeneratePresharedKey()
	if err != nil {
		t.Fatalf("GeneratePresharedKey failed: %v", err)
	}
	if len(psk) != 44 {
		t.Errorf("expected 44-char base64 psk, got %d", len(psk))
	}
}
