package mediakeys

import "errors"

var (
	ErrNilExporter                  = errors.New("mediakeys: exporter nil")
	ErrNilExporterSecret            = errors.New("mediakeys: exporter secret nil")
	ErrInvalidBaseSecret            = errors.New("mediakeys: invalid base secret length")
	ErrGenerationExpired            = errors.New("mediakeys: generation expired")
	ErrDisplayableGroupSizeTooLarge = errors.New("mediakeys: displayable code group size must be < 8")
	ErrDisplayableGroupSizeInvalid  = errors.New("mediakeys: displayable code group size must be > 0")
	ErrDisplayableCodeLenInvalid    = errors.New("mediakeys: displayable code length must be a positive multiple of group size")
	ErrDisplayableCodeInputTooShort = errors.New("mediakeys: displayable code input shorter than required by code length and group size")
	ErrGenerationTooFar             = errors.New("mediakeys: generation gap exceeds maximum")
)
