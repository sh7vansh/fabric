package protocol

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeExtractPath(t *testing.T) {
	destDir := "/tmp/safe/dir"

	validTests := []string{
		"file.txt",
		"sub/dir/file.txt",
		"./file.txt",
	}

	for _, p := range validTests {
		target, err := SanitizeExtractPath(destDir, p)
		if err != nil {
			t.Errorf("SanitizeExtractPath(%q, %q) unexpected error: %v", destDir, p, err)
		}
		if !filepath.IsAbs(target) {
			t.Errorf("expected absolute path, got %q", target)
		}
	}

	invalidTests := []string{
		"../escape.txt",
		"../../etc/passwd",
		"sub/../../escape.txt",
		"/etc/passwd",
	}

	for _, p := range invalidTests {
		_, err := SanitizeExtractPath(destDir, p)
		if err == nil {
			t.Errorf("SanitizeExtractPath(%q, %q) expected error for path traversal, got nil", destDir, p)
		}
	}
}

func TestTarCreateAndExtract(t *testing.T) {
	tempDir := t.TempDir()
	srcDir := filepath.Join(tempDir, "source")
	os.MkdirAll(filepath.Join(srcDir, "nested"), 0755)
	os.WriteFile(filepath.Join(srcDir, "hello.txt"), []byte("world"), 0644)
	os.WriteFile(filepath.Join(srcDir, "nested", "inner.txt"), []byte("inner content"), 0644)

	var buf bytes.Buffer
	if err := CreateTar(&buf, srcDir); err != nil {
		t.Fatalf("CreateTar failed: %v", err)
	}

	destDir := filepath.Join(tempDir, "dest")
	if err := ExtractTar(&buf, destDir); err != nil {
		t.Fatalf("ExtractTar failed: %v", err)
	}

	extractedFile := filepath.Join(destDir, "source", "hello.txt")
	content, err := os.ReadFile(extractedFile)
	if err != nil || string(content) != "world" {
		t.Errorf("expected 'world', got content=%q, err=%v", string(content), err)
	}

	extractedNested := filepath.Join(destDir, "source", "nested", "inner.txt")
	nestedContent, err := os.ReadFile(extractedNested)
	if err != nil || string(nestedContent) != "inner content" {
		t.Errorf("expected 'inner content', got content=%q, err=%v", string(nestedContent), err)
	}
}

func TestExtractTarRejectsTarSlip(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	body := []byte("malicious content")
	hdr := &tar.Header{
		Name: "../../../tmp/escaped_test_file.txt",
		Mode: 0644,
		Size: int64(len(body)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	tw.Write(body)
	tw.Close()

	destDir := t.TempDir()
	err := ExtractTar(&buf, destDir)
	if err == nil {
		t.Fatal("ExtractTar expected error for Tar Slip archive, got nil")
	}
}

func TestExtractTarEntryCountLimit(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for i := 0; i < 20; i++ {
		hdr := &tar.Header{
			Name: fmt.Sprintf("file_%d.txt", i),
			Mode: 0644,
			Size: 4,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte("test"))
	}
	tw.Close()

	destDir := t.TempDir()
	// Test with a maxEntries limit of 10
	err := ExtractTarWithLimits(&buf, destDir, 1024*1024, 10)
	if err == nil {
		t.Fatalf("expected ExtractTarWithLimits to fail on entry count > 10, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum entry count") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestExtractTarDecompressedSizeLimit(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	payload := make([]byte, 2048)
	hdr := &tar.Header{
		Name: "large_file.bin",
		Mode: 0644,
		Size: int64(len(payload)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	tw.Write(payload)
	tw.Close()

	destDir := t.TempDir()
	// Limit extraction to 1024 bytes max
	err := ExtractTarWithLimits(&buf, destDir, 1024, 100)
	if err == nil {
		t.Fatalf("expected ExtractTarWithLimits to fail on exceeding max size, got nil")
	}
	if !strings.Contains(err.Error(), "exceeded maximum decompressed size") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestExtractTarStrippingSUIDBits(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	body := []byte("executable script")
	hdr := &tar.Header{
		Name: "suid_script.sh",
		Mode: 04755, // Setuid bit set
		Size: int64(len(body)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	tw.Write(body)
	tw.Close()

	destDir := t.TempDir()
	if err := ExtractTar(&buf, destDir); err != nil {
		t.Fatalf("ExtractTar failed: %v", err)
	}

	fi, err := os.Stat(filepath.Join(destDir, "suid_script.sh"))
	if err != nil {
		t.Fatal(err)
	}

	// Verify SUID and SGID bits are stripped
	if fi.Mode()&os.ModeSetuid != 0 || fi.Mode()&os.ModeSetgid != 0 {
		t.Errorf("expected SUID/SGID bits to be stripped, got mode: %v", fi.Mode())
	}
	// Perm should be 0755
	if fi.Mode().Perm() != 0755 {
		t.Errorf("expected permission 0755, got: %o", fi.Mode().Perm())
	}
}

func TestExtractTarSymlinkEscape(t *testing.T) {
	destDir := t.TempDir()

	// Create a symlink inside destDir pointing outside
	outsideDir := t.TempDir()
	symlinkPath := filepath.Join(destDir, "symlink_dir")
	if err := os.Symlink(outsideDir, symlinkPath); err != nil {
		t.Fatal(err)
	}

	// Now try to extract a file to symlink_dir/evil.txt
	_, err := SanitizeExtractPath(destDir, "symlink_dir/evil.txt")
	if err == nil {
		t.Errorf("expected SanitizeExtractPath to reject traversing symlink pointing outside destDir")
	}
}

func TestExtractTarLeafSymlinkEscape(t *testing.T) {
	destDir := t.TempDir()
	outsideDir := t.TempDir()
	outsideTarget := filepath.Join(outsideDir, "pwned.txt")
	_ = os.WriteFile(outsideTarget, []byte("original"), 0644)

	// Create a leaf symlink inside destDir that points to outsideTarget
	leafSymlink := filepath.Join(destDir, "leaf_link.txt")
	if err := os.Symlink(outsideTarget, leafSymlink); err != nil {
		t.Fatal(err)
	}

	// Try sanitizing and extracting an entry named "leaf_link.txt"
	_, err := SanitizeExtractPath(destDir, "leaf_link.txt")
	if err == nil {
		t.Errorf("expected SanitizeExtractPath to reject leaf symlink pointing outside destDir")
	}
}

