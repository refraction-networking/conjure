package client

// Fixed-Size-Payload has a 1 byte flags field.
// bit 0 (1 << 7) determines if flow is bidirectional(0) or upload-only(1)
// bit 1 (1 << 6) enables dark-decoys
// bits 2-5 are unassigned
// bit 6 determines whether PROXY-protocol-formatted string will be sent
// bit 7 (1 << 0) signals to use TypeLen outer proto
var (
	flagUploadOnly  = uint8(1 << 7)
	flagProxyHeader = uint8(1 << 1)
	flagUseTIL      = uint8(1 << 0)
)

var defaultFlags = flagUseTIL
