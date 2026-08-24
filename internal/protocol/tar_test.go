package protocol

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
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
