package codecs

import "errors"

// ErrCodecNotSupported is returned by the Encrypt entry points for any codec
// other than Opus. dave-go targets Discord audio (Opus); the video codecs
// (VP8, VP9, H264, H265, AV1) are out of scope and rejected loudly so a caller
// cannot silently exercise the unaudited video paths — most importantly the
// H26x nonce-retry path, whose failure mode is an invisible AES-GCM nonce
// reuse. The codec-specific logic remains in the package (behind internal
// functions) so video can be re-enabled deliberately in the future.
var ErrCodecNotSupported = errors.New("codecs: codec not supported (dave-go encrypts Opus audio only)")
