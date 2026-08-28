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

var defaultAuthorizedRoots = []string{
	"/home",
	"/tmp",
	"/var/tmp",
	"/var/www",
	"/var/log",
	"/opt",
	"/srv",
	"/mnt",
	"/media",
	"/data",
	"/usr/local",
}

// AuthorizeDestinationPath verifies that a target destination path strictly resides
// within authorized capability roots without path traversal, escaping relative components,
// or intermediate/leaf symlink dereferencing to unauthorized locations.
func AuthorizeDestinationPath(targetPath string, allowedRoots ...string) (string, error) {
	if strings.ContainsRune(targetPath, 0) {
		return "", fmt.Errorf("invalid path: contains null bytes")
	}

	rawClean := filepath.Clean(targetPath)
	if !filepath.IsAbs(rawClean) {
		if strings.HasPrefix(rawClean, "..") || strings.HasPrefix(rawClean, "/..") {
			return "", fmt.Errorf("path traversal: destination path %q escapes root", targetPath)
		}
		return rawClean, nil
	}

	clean := rawClean
	if clean == "/" {
		return "", fmt.Errorf("access denied: destination %q is the filesystem root", targetPath)
	}

	roots := allowedRoots
	if len(roots) == 0 {
		roots = defaultAuthorizedRoots
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			roots = append(roots, home)
		}
	}

	// Evaluate symlinks on deepest existing ancestor to ensure symlink dereferencing stays within authorized roots
	checkPath := clean
	for {
		if fi, err := os.Lstat(checkPath); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				eval, err := filepath.EvalSymlinks(checkPath)
				if err != nil {
					return "", fmt.Errorf("access denied: broken or invalid symlink in path %q: %w", targetPath, err)
				}
				rel, _ := filepath.Rel(checkPath, clean)
				if rel == "." {
					clean = eval
				} else {
					clean = filepath.Join(eval, rel)
				}
			}
			break
		}
		parent := filepath.Dir(checkPath)
		if parent == checkPath || parent == "/" || parent == "." {
			break
		}
		checkPath = parent
	}

	isAuthorized := false
	for _, root := range roots {
		cleanRoot := filepath.Clean(root)
		if clean == cleanRoot {
			isAuthorized = true
			break
		}
		rel, err := filepath.Rel(cleanRoot, clean)
		if err == nil && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." {
			isAuthorized = true
			break
		}
	}

	if !isAuthorized {
		return "", fmt.Errorf("access denied: destination %q is not within authorized roots", targetPath)
	}

	return clean, nil
}

// ValidateDestinationPath ensures a file transfer target is within authorized capability roots.
func ValidateDestinationPath(path string) error {
	_, err := AuthorizeDestinationPath(path)
	return err
}

// TarStats contains summary metrics of an archive operation.
type TarStats struct {
	Bytes int64
	Files int
}

// ExtractTar reads a tar stream from r and unpacks it safely inside destDir with default limits.
func ExtractTar(r io.Reader, destDir string) error {
	_, err := ExtractTarWithStats(r, destDir)
	return err
}

// ExtractTarWithStats reads a tar stream and unpacks it returning transfer statistics.
func ExtractTarWithStats(r io.Reader, destDir string) (TarStats, error) {
	return ExtractTarWithLimitsStats(r, destDir, MaxTarDecompressedSize, MaxTarEntryCount)
}

// ExtractTarWithLimits reads a tar stream and unpacks it enforcing explicit decompressed size and entry bounds.
func ExtractTarWithLimits(r io.Reader, destDir string, maxBytes int64, maxEntries int) error {
	_, err := ExtractTarWithLimitsStats(r, destDir, maxBytes, maxEntries)
	return err
}

// ExtractTarWithLimitsStats reads a tar stream and unpacks it enforcing explicit bounds while returning metrics.
func ExtractTarWithLimitsStats(r io.Reader, destDir string, maxBytes int64, maxEntries int) (TarStats, error) {
	stats := TarStats{}
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
			return stats, fmt.Errorf("failed to create staging directory: %w", err)
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
			return stats, err
		}

		entryCount++
		if entryCount > maxEntries {
			return stats, fmt.Errorf("tar archive exceeds maximum entry count of %d", maxEntries)
		}

		targetPath, err := SanitizeExtractPath(stagingDir, header.Name)
		if err != nil {
			return stats, err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return stats, err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return stats, err
			}

			// Strip SUID/SGID bits and enforce safe permission masking
			rawPerm := header.FileInfo().Mode().Perm() & 0755
			fileMode := os.FileMode(0644)
			if rawPerm&0111 != 0 {
				fileMode = 0755
			}

			remainingBytes := maxBytes - totalDecompressedBytes
			if remainingBytes <= 0 || header.Size > remainingBytes {
				return stats, fmt.Errorf("tar extraction exceeded maximum decompressed size limit of %d bytes", maxBytes)
			}

			f, err := os.OpenFile(targetPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, fileMode)
			if err != nil {
				return stats, err
			}

			copied, err := io.Copy(f, io.LimitReader(tr, remainingBytes+1))
			f.Close()
			if err != nil {
				return stats, err
			}

			totalDecompressedBytes += copied
			if totalDecompressedBytes > maxBytes {
				return stats, fmt.Errorf("tar extraction exceeded maximum decompressed size limit of %d bytes", maxBytes)
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return stats, err
			}
			linkTarget := header.Linkname
			if filepath.IsAbs(linkTarget) || strings.HasPrefix(linkTarget, "/") || strings.HasPrefix(linkTarget, "\\") {
				return stats, fmt.Errorf("tar extraction rejected unsafe absolute symlink %q -> %q", header.Name, linkTarget)
			}
			resolvedLink := filepath.Join(filepath.Dir(targetPath), linkTarget)
			cleanResolved := filepath.Clean(resolvedLink)
			relToStaging, err := filepath.Rel(stagingDir, cleanResolved)
			if err != nil || strings.HasPrefix(relToStaging, "..") || relToStaging == ".." {
				return stats, fmt.Errorf("tar extraction rejected escaping symlink %q -> %q", header.Name, linkTarget)
			}
			_ = os.Remove(targetPath)
			if err := os.Symlink(linkTarget, targetPath); err != nil {
				return stats, fmt.Errorf("failed to create extracted symlink: %w", err)
			}
		}
	}

	if entryCount == 0 {
		return stats, fmt.Errorf("archive contains no files or remote path not found")
	}

	// Commit staged files to target destination atomically
	if err := commitStagedDirectory(stagingDir, cleanDest); err != nil {
		return stats, fmt.Errorf("failed to commit staged archive: %w", err)
	}

	stats.Bytes = totalDecompressedBytes
	stats.Files = entryCount
	return stats, nil
}

func commitStagedDirectory(stagingDir, destDir string) error {
	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}

	destStat, destErr := os.Stat(destDir)
	isExistingDir := destErr == nil && destStat.IsDir()
	explicitDir := strings.HasSuffix(destDir, "/") || strings.HasSuffix(destDir, string(filepath.Separator))

	// If destDir is not an explicit or existing directory, and the archive contains a single regular file, commit directly as that file.
	if !isExistingDir && !explicitDir && len(entries) == 1 && !entries[0].IsDir() {
		if err := os.MkdirAll(filepath.Dir(destDir), 0755); err != nil {
			return err
		}
		src := filepath.Join(stagingDir, entries[0].Name())
		dst := destDir
		if _, err := os.Lstat(dst); err == nil {
			_ = os.RemoveAll(dst)
		}
		if err := os.Rename(src, dst); err != nil {
			if err := copyRecursive(src, dst); err != nil {
				return err
			}
			_ = os.RemoveAll(src)
		}
		return nil
	}

	if err := os.MkdirAll(destDir, 0755); err != nil {
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
	_, err := CreateTarWithStats(w, srcPath)
	return err
}

// CreateTarWithStats writes the file or directory at srcPath as a tar stream to w and returns archive statistics.
func CreateTarWithStats(w io.Writer, srcPath string) (TarStats, error) {
	stats := TarStats{}
	cleanSrc := filepath.Clean(srcPath)
	info, err := os.Stat(cleanSrc)
	if err != nil {
		return stats, err
	}

	tw := tar.NewWriter(w)
	defer tw.Close()

	if !info.IsDir() {
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return stats, err
		}
		header.Name = filepath.Base(cleanSrc)
		if err := tw.WriteHeader(header); err != nil {
			return stats, err
		}
		f, err := os.Open(cleanSrc)
		if err != nil {
			return stats, err
		}
		defer f.Close()
		copied, err := io.Copy(tw, f)
		if err != nil {
			return stats, err
		}
		stats.Bytes = copied
		stats.Files = 1
		return stats, nil
	}

	baseDir := filepath.Dir(cleanSrc)
	err = filepath.Walk(cleanSrc, func(path string, fi os.FileInfo, err error) error {
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
			copied, err := io.Copy(tw, f)
			if err != nil {
				return err
			}
			stats.Bytes += copied
			stats.Files++
		}
		return nil
	})
	return stats, err
}
