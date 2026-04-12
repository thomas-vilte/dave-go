package mediakeys

import "errors"

var (
	ErrNilExporter       = errors.New("mediakeys: exporter nil")
	ErrInvalidBaseSecret = errors.New("mediakeys: invalid base secret length")
	ErrGenerationExpired = errors.New("mediakeys: generation expired")
)
