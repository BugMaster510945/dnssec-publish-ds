package plugin

import "time"

// KeyRecord represents a DNSSEC key with both CDS and optional CDNSKEY data.
type KeyRecord struct {
	// CDS fields (always present - computed from CDNSKEY if not in DNS)
	Tag        uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string

	// CDNSKEY fields (optional - nil if only CDS was available)
	Flags     *uint16
	Protocol  *uint8
	PublicKey *string
}

// UpdateRequest describes the changes that need to be applied to a zone.
type UpdateRequest struct {
	Zone     string
	ToAdd    []KeyRecord
	ToRemove []KeyRecord
	Raw      map[string]any
}

// UpdateResult is returned by Update.
// InProgress indicates if an operation is still running and should be called
// again with the returned Raw state.
// Raw holds provider-specific state (opaque to core, may contain plugin's internal FSM state).
type UpdateResult struct {
	InProgress bool           `json:"in_progress"`
	Raw        map[string]any `json:"raw,omitempty"`
	NextWait   time.Duration  `json:"next_wait,omitempty"`
}

// Capabilities describes what a plugin requires from the core.
type Capabilities struct {
	// RequiresCDNSKEY indicates that the plugin needs CDNSKEY data (flags,
	// protocol, public key) and cannot work with CDS alone.
	RequiresCDNSKEY bool
}
