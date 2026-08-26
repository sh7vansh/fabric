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

func TestValidateDestinationPath(t *testing.T) {
	protected := []string{
		"/etc",
		"/etc/shadow",
		"/etc/passwd",
		"/root",
		"/root/.ssh/authorized_keys",
		"/sys/kernel",
		"/proc/1/cmdline",
		"/boot/vmlinuz",
		"/dev/null",
	}

	for _, p := range protected {
		if err := ValidateDestinationPath(p); err == nil {
			t.Errorf("ValidateDestinationPath(%q) expected error for protected system path, got nil", p)
		}
	}

	valid := []string{
		"/home/user/project",
		"/tmp/app",
		"/var/www/html",
		"relative/path",
		"./local",
	}

	for _, p := range valid {
		if err := ValidateDestinationPath(p); err != nil {
			t.Errorf("ValidateDestinationPath(%q) unexpected error for valid path: %v", p, err)
		}
	}

	traversal := []string{
		"../escape",
		"../../etc/shadow",
	}

	for _, p := range traversal {
		if err := ValidateDestinationPath(p); err == nil {
			t.Errorf("ValidateDestinationPath(%q) expected error for path traversal, got nil", p)
		}
	}
}

func TestExtractTarAtomicCleanupOnInterruption(t *testing.T) {
	destDir := filepath.Join(t.TempDir(), "target_dir")
	// Pre-create some content in destDir
	_ = os.MkdirAll(destDir, 0755)
	existingFile := filepath.Join(destDir, "original.txt")
	_ = os.WriteFile(existingFile, []byte("preserve me"), 0644)

	// Interrupted stream with truncated data
	corruptedStream := bytes.NewReader([]byte("not a valid tar header stream"))

	err := ExtractTar(corruptedStream, destDir)
	if err == nil {
		t.Fatalf("expected error on corrupted stream, got nil")
	}

	// Verify existing files were preserved and not corrupted
	content, err := os.ReadFile(existingFile)
	if err != nil || string(content) != "preserve me" {
		t.Errorf("expected original.txt to be preserved, got content=%q, err=%v", string(content), err)
	}

	// Verify no residual staging directories left behind
	parentDir := filepath.Dir(destDir)
	entries, _ := os.ReadDir(parentDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".fabric-staging-") {
			t.Errorf("found residual staging directory: %s", e.Name())
		}
	}
}

func TestExtractTarSingleFileDestination(t *testing.T) {
	tempDir := t.TempDir()
	srcFile := filepath.Join(tempDir, "source.txt")
	if err := os.WriteFile(srcFile, []byte("single file content"), 0644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := CreateTar(&buf, srcFile); err != nil {
		t.Fatalf("CreateTar failed: %v", err)
	}

	destFile := filepath.Join(tempDir, "renamed.txt")
	if err := ExtractTar(&buf, destFile); err != nil {
		t.Fatalf("ExtractTar failed: %v", err)
	}

	fi, err := os.Stat(destFile)
	if err != nil {
		t.Fatalf("os.Stat(destFile) failed: %v", err)
	}
	if fi.IsDir() {
		t.Fatalf("expected destFile %q to be a regular file, but it is a directory", destFile)
	}

	content, err := os.ReadFile(destFile)
	if err != nil {
		t.Fatalf("os.ReadFile failed: %v", err)
	}
	if string(content) != "single file content" {
		t.Fatalf("expected 'single file content', got %q", string(content))
	}
}



