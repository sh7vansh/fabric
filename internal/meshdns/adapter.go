package meshdns

// OSEnvironment provides an interface for interacting with the operating system's DNS settings.
type OSEnvironment interface {
	// AddDNSOverride adds a DNS override for the given domain to the specified IP address.
	AddDNSOverride(domain string, ip string) error

	// RemoveDNSOverride removes a DNS override for the given domain.
	RemoveDNSOverride(domain string) error

	// Close reverts any changes made to the OS environment and releases any resources.
	Close() error
}
