package cli

import (
	"fmt"
	"io"
	"os"
	"sync"
)

var (
	depMu             sync.Mutex
	deprecationWriter io.Writer = os.Stderr
)

// SetDeprecationWriter overrides the destination for deprecation warnings (useful for tests).
func SetDeprecationWriter(w io.Writer) {
	depMu.Lock()
	defer depMu.Unlock()
	deprecationWriter = w
}

// WarnDeprecated prints a standardized deprecation notice to stderr.
func WarnDeprecated(deprecated, replacement string) {
	depMu.Lock()
	defer depMu.Unlock()
	if deprecationWriter != nil {
		fmt.Fprintf(deprecationWriter, "Warning: '%s' is deprecated. Use '%s' instead.\n", deprecated, replacement)
	}
}
