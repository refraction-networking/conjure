package client

// IPSupport is a bitmask of supported IP versions.
type IPSupport int

func (s IPSupport) String() string {
	if (s&V4 == V4) && (s&V6 == V6) {
		return "Both"
	} else if s&V4 == V4 {
		return "V4"
	} else if s&V6 == V6 {
		return "V6"
	} else {
		return "unknown"
	}
}

const (
	// V4 indicates that a client session supports attempting IPv4 connections
	V4 IPSupport = 1 << iota
	// V6 indicates that a client session supports attempting IPv4 connections
	V6
)
