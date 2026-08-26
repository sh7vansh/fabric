package protocol

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Constants for resource-bounded tar extraction.
const (
	MaxTarDecompressedSize int64 = 5 * 1024 * 1024 * 1024 // 5 GB
	MaxTarEntryCount             = 10000                  // 10,000 files
)

// SanitizeExtractPath checks whether the entry name stays strictly inside destDir.
func SanitizeExtractPath(destDir, entryName string) (string, error) {
	if filepath.IsAbs(entryName) || strings.HasPrefix(entryName, "/") || strings.HasPrefix(entryName, "\\") {
		return "", fmt.Errorf("path traversal detected: absolute path %q is not permitted", entryName)
	}

	cleanDest := filepath.Clean(destDir)
	target := filepath.Join(cleanDest, entryName)
	cleanTarget := filepath.Clean(target)

	rel, err := filepath.Rel(cleanDest, cleanTarget)
	if err != nil || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return "", fmt.Errorf("path traversal detected: %q escapes %q", entryName, destDir)
	}

	// Symlink escape check: Ensure all path components (intermediate and leaf) do not resolve to a symlink escaping destDir
	current := cleanDest
	parts := strings.Split(rel, string(filepath.Separator))
	for i := 0; i < len(parts); i++ {
		current = filepath.Join(current, parts[i])
		if fi, err := os.Lstat(current); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				eval, err := filepath.EvalSymlinks(current)
				if err != nil {
					return "", fmt.Errorf("path traversal detected in symlink: %w", err)
				}
				evalRel, err := filepath.Rel(cleanDest, eval)
				if err != nil || strings.HasPrefix(evalRel, ".."+string(filepath.Separator)) || evalRel == ".." {
					return "", fmt.Errorf("path traversal detected: symlink %q escapes %q", current, destDir)
				}
			}
		}
	}

	return cleanTarget, nil
}

var protectedSystemPrefixes = []string{
	"/etc",
	"/root",
	"/sys",
	"/proc",
	"/boot",
	"/dev",
	"/run",
	"/sbin",
	"/usr/sbin",
	"/lib",
	"/lib64",
}

// ValidateDestinationPath ensures a file transfer target is not an unauthorized protected system directory.
func ValidateDestinationPath(path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		if strings.HasPrefix(clean, "..") {
			return fmt.Errorf("path traversal: destination path %q escapes root", path)
		}
		return nil
	}

	for _, prefix := range protectedSystemPrefixes {
		if clean == prefix || strings.HasPrefix(clean, prefix+string(filepath.Separator)) {
			return fmt.Errorf("access denied: destination %q is a protected system directory", path)
		}
	}
	return nil
}

// ExtractTar reads a tar stream from r and unpacks it safely inside destDir with default limits.
func ExtractTar(r io.Reader, destDir string) error {
	return ExtractTarWithLimits(r, destDir, MaxTarDecompressedSize, MaxTarEntryCount)
}

// ExtractTarWithLimits reads a tar stream and unpacks it enforcing explicit decompressed size and entry bounds.
func ExtractTarWithLimits(r io.Reader, destDir string, maxBytes int64, maxEntries int) error {
	if maxBytes <= 0 {
		maxBytes = MaxTarDecompressedSize
	}
	if maxEntries <= 0 {
		maxEntries = MaxTarEntryCount
	}

	cleanDest := filepath.Clean(destDir)
	parentDir := filepath.Dir(cleanDest)
	_ = os.MkdirAll(parentDir, 0755)

	stagingDir, err := os.MkdirTemp(parentDir, ".fabric-staging-*")
	if err != nil {
		stagingDir, err = os.MkdirTemp("", ".fabric-staging-*")
		if err != nil {
			return fmt.Errorf("failed to create staging directory: %w", err)
		}
	}
	defer func() {
		if stagingDir != "" {
			_ = os.RemoveAll(stagingDir)
		}
	}()

	tr := tar.NewReader(io.LimitReader(r, maxBytes))
	var totalDecompressedBytes int64
	var entryCount int

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		entryCount++
		if entryCount > maxEntries {
			return fmt.Errorf("tar archive exceeds maximum entry count of %d", maxEntries)
		}

		targetPath, err := SanitizeExtractPath(stagingDir, header.Name)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return err
			}

			// Strip SUID/SGID bits and enforce safe permission masking
			rawPerm := header.FileInfo().Mode().Perm() & 0755
			fileMode := os.FileMode(0644)
			if rawPerm&0111 != 0 {
				fileMode = 0755
			}

			remainingBytes := maxBytes - totalDecompressedBytes
			if remainingBytes <= 0 || header.Size > remainingBytes {
				return fmt.Errorf("tar extraction exceeded maximum decompressed size limit of %d bytes", maxBytes)
			}

			f, err := os.OpenFile(targetPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, fileMode)
			if err != nil {
				return err
			}

			copied, err := io.Copy(f, io.LimitReader(tr, remainingBytes+1))
			f.Close()
			if err != nil {
				return err
			}

			totalDecompressedBytes += copied
			if totalDecompressedBytes > maxBytes {
				return fmt.Errorf("tar extraction exceeded maximum decompressed size limit of %d bytes", maxBytes)
			}
		}
	}

	// Commit staged files to target destination atomically
	if err := commitStagedDirectory(stagingDir, cleanDest); err != nil {
		return fmt.Errorf("failed to commit staged archive: %w", err)
	}

	return nil
}

func commitStagedDirectory(stagingDir, destDir string) error {
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		src := filepath.Join(stagingDir, entry.Name())
		dst := filepath.Join(destDir, entry.Name())

		// Remove existing destination item if present
		if _, err := os.Lstat(dst); err == nil {
			_ = os.RemoveAll(dst)
		}

		if err := os.Rename(src, dst); err != nil {
			// Fallback recursive copy if rename fails across filesystems
			if err := copyRecursive(src, dst); err != nil {
				return err
			}
			_ = os.RemoveAll(src)
		}
	}

	return nil
}

func copyRecursive(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}

	if info.IsDir() {
		if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := copyRecursive(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
		}
		return nil
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// CreateTar writes the file or directory at srcPath as a tar stream to w.
func CreateTar(w io.Writer, srcPath string) error {
	cleanSrc := filepath.Clean(srcPath)
	info, err := os.Stat(cleanSrc)
	if err != nil {
		return err
	}

	tw := tar.NewWriter(w)
	defer tw.Close()

	if !info.IsDir() {
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = filepath.Base(cleanSrc)
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		f, err := os.Open(cleanSrc)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	}

	baseDir := filepath.Dir(cleanSrc)
	return filepath.Walk(cleanSrc, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(baseDir, path)
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(rel)
		if fi.IsDir() {
			header.Name += "/"
		}
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(tw, f)
			return err
		}
		return nil
	})
}
