package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
)

// StitchTarget holds resolved connection parameters for stitching a remote machine.
type StitchTarget struct {
	Host   string `json:"host"`
	Port   string `json:"port"`
	User   string `json:"user,omitempty"`
	Banner string `json:"banner,omitempty"`
}

// TargetSpec returns the formatted SSH target string, e.g. "user@192.168.1.10:22".
func (t StitchTarget) TargetSpec() string {
	target := t.Host
	if t.User != "" {
		target = t.User + "@" + target
	}
	if t.Port != "" && t.Port != "22" {
		target = target + ":" + t.Port
	}
	return target
}

// PrintDiscoveryTable prints a formatted table of discovered SSH hosts.
func PrintDiscoveryTable(w io.Writer, hosts []DiscoveredHost) {
	if len(hosts) == 0 {
		fmt.Fprintln(w, "No SSH endpoints discovered.")
		return
	}

	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	fmt.Fprintf(tw, "NUM\tENDPOINT\tBANNER\tLATENCY\n")
	for i, h := range hosts {
		endpoint := h.IP
		if h.Port != 22 {
			endpoint = fmt.Sprintf("%s:%d", h.IP, h.Port)
		}
		banner := h.CleanBanner
		if banner == "" {
			banner = h.Banner
		}
		fmt.Fprintf(tw, "[%d]\t%s\t%s\t%s\n", i+1, endpoint, banner, h.Latency)
	}
	tw.Flush()
}

// FormatDiscoveredOutput prints hosts in quiet or JSON format.
func FormatDiscoveredOutput(w io.Writer, hosts []DiscoveredHost, quiet bool, format string) error {
	if format == "json" {
		b, err := json.MarshalIndent(hosts, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(w, string(b))
		return nil
	}

	if quiet {
		for _, h := range hosts {
			if h.Port != 22 {
				fmt.Fprintf(w, "%s:%d\n", h.IP, h.Port)
			} else {
				fmt.Fprintln(w, h.IP)
			}
		}
		return nil
	}

	PrintDiscoveryTable(w, hosts)
	return nil
}

// ParseSelectionInput parses user selection expressions like:
// "all", "1, 3", "admin@2", "3:2222", "root@4:2222", "1-3", "admin@1-3:2222"
func ParseSelectionInput(input string, hosts []DiscoveredHost, defaultUser string) ([]StitchTarget, error) {
	input = strings.TrimSpace(input)
	if input == "" || strings.ToLower(input) == "q" || strings.ToLower(input) == "quit" || strings.ToLower(input) == "exit" {
		return nil, nil
	}

	if strings.ToLower(input) == "all" || strings.ToLower(input) == "*" {
		var selected []StitchTarget
		for _, h := range hosts {
			selected = append(selected, StitchTarget{
				Host:   h.IP,
				Port:   strconv.Itoa(h.Port),
				User:   defaultUser,
				Banner: h.CleanBanner,
			})
		}
		return selected, nil
	}

	var selected []StitchTarget
	seen := make(map[string]bool)

	tokens := strings.Split(input, ",")
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}

		userOverride := defaultUser
		portOverride := ""
		targetIdentifier := token

		if atIdx := strings.Index(targetIdentifier, "@"); atIdx != -1 {
			userOverride = targetIdentifier[:atIdx]
			targetIdentifier = targetIdentifier[atIdx+1:]
		}

		if colonIdx := strings.LastIndex(targetIdentifier, ":"); colonIdx != -1 {
			portOverride = targetIdentifier[colonIdx+1:]
			targetIdentifier = targetIdentifier[:colonIdx]
		}

		// Check if targetIdentifier is a numeric range e.g. "1-3"
		if strings.Contains(targetIdentifier, "-") {
			rangeParts := strings.Split(targetIdentifier, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err1 == nil && err2 == nil {
					if start < 1 || end > len(hosts) || start > end {
						return nil, fmt.Errorf("invalid selection range [%s]: out of range (1-%d)", targetIdentifier, len(hosts))
					}
					for i := start; i <= end; i++ {
						h := hosts[i-1]
						port := strconv.Itoa(h.Port)
						if portOverride != "" {
							port = portOverride
						}
						key := fmt.Sprintf("%s@%s:%s", userOverride, h.IP, port)
						if !seen[key] {
							seen[key] = true
							selected = append(selected, StitchTarget{
								Host:   h.IP,
								Port:   port,
								User:   userOverride,
								Banner: h.CleanBanner,
							})
						}
					}
					continue
				}
			}
		}

		// Check if targetIdentifier is a single index number (1-based)
		idx, err := strconv.Atoi(targetIdentifier)
		if err == nil {
			if idx < 1 || idx > len(hosts) {
				return nil, fmt.Errorf("invalid selection index [%d]: out of range (1-%d)", idx, len(hosts))
			}
			h := hosts[idx-1]
			port := strconv.Itoa(h.Port)
			if portOverride != "" {
				port = portOverride
			}

			key := fmt.Sprintf("%s@%s:%s", userOverride, h.IP, port)
			if !seen[key] {
				seen[key] = true
				selected = append(selected, StitchTarget{
					Host:   h.IP,
					Port:   port,
					User:   userOverride,
					Banner: h.CleanBanner,
				})
			}
		} else {
			// Direct IP or Hostname entered
			port := "22"
			if portOverride != "" {
				port = portOverride
			}
			key := fmt.Sprintf("%s@%s:%s", userOverride, targetIdentifier, port)
			if !seen[key] {
				seen[key] = true
				selected = append(selected, StitchTarget{
					Host: targetIdentifier,
					Port: port,
					User: userOverride,
				})
			}
		}
	}

	return selected, nil
}
