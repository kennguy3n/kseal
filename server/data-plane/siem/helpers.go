package siem

import (
	"strings"
	"time"
)

// nowUnix is the current unix time in seconds. A package var so tests can pin it.
var nowUnix = func() int64 { return time.Now().Unix() }

// secretRef derives the opaque, non-sensitive reference surfaced on a connector
// for the sealed auth secret. It encodes nothing secret — just a stable handle
// derived from the connector id — so it is safe to return over RPC and display.
func secretRef(connectorID string) string {
	id := strings.ReplaceAll(connectorID, "-", "")
	if len(id) > 12 {
		id = id[:12]
	}
	return "siem_sec_" + id
}
