// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package util

// FilestoreVersion signifies the version of the filestore directory layout
type FilestoreVersion int

const (
	// V1 means file store version 1, pre-4.1 Suricata
	V1 FilestoreVersion = 1
	// V2 means file store version 2, Suricata 4.1 or later
	V2 FilestoreVersion = 2
)
