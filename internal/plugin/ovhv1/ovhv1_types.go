package ovhv1

import (
	"log/slog"
	"time"

	"github.com/ovh/go-ovh/ovh"

	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/plugin"
)

const pluginName = "ovh-v1"

const (
	defaultWaitSubmit      = 30 * time.Second
	defaultWaitPollUrgent  = 30 * time.Second
	defaultWaitPollPassive = 5 * time.Minute
)

// No longer needed - states are simplified

// OVHv1Plugin is the global plugin object for OVH v1.
type OVHv1Plugin struct {
	log             *slog.Logger
	throttle        *plugin.Limiter
	waitSubmit      time.Duration
	waitPollUrgent  time.Duration
	waitPollPassive time.Duration
}

// OVHv1Group is the group-specific OVH plugin instance.
type OVHv1Group struct {
	plugin            *OVHv1Plugin
	client            *ovh.Client
	log               *slog.Logger
	allowAcceleration bool
}

// ovhKey is the representation of a DNSSEC key in the OVH API.
type ovhKey struct {
	ID        int    `json:"id,omitempty"`
	Algorithm int    `json:"algorithm"`
	Flags     int    `json:"flags"`
	PublicKey string `json:"publicKey"`
	Tag       int    `json:"tag"`
	Status    string `json:"status,omitempty"`
}

// ovhDSPayload is the body sent to POST /domain/{zone}/dsRecord.
type ovhDSPayload struct {
	Keys []ovhKey `json:"keys"`
}

// ovhTask represents an OVH domain task.
type ovhTask struct {
	ID            int    `json:"id"`
	Function      string `json:"function"`
	Status        string `json:"status"`
	CanAccelerate bool   `json:"canAccelerate"`
	CanCancel     bool   `json:"canCancel"`
	CanRelaunch   bool   `json:"canRelaunch"`
}

// ovhMe is the subset of /me fields we care about.
type ovhMe struct {
	Nichandle string `json:"nichandle"`
}
