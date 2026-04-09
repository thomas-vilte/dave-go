package mediakeys

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// ExportWithMLSExporterSecret derives application secret material directly from
// an MLS exporter secret using the label/context construction expected by
// Discord's DAVE reference implementations.
func ExportWithMLSExporterSecret(exporterSecret *ciphersuite.Secret, cs ciphersuite.CipherSuite, label string, context []byte, length int) ([]byte, error) {
	if exporterSecret == nil {
		return nil, fmt.Errorf("exporter_secret is nil")
	}

	derivedSecret, err := exporterSecret.DeriveSecret(cs, label)
	if err != nil {
		return nil, fmt.Errorf("derive exporter label %q: %w", label, err)
	}

	contextHash, err := ciphersuite.Hash(cs, context)
	if err != nil {
		return nil, fmt.Errorf("hash exporter context: %w", err)
	}

	// Discord's DAVE protocol uses mlspp which uses "exported" (not "exporter") in step 2.
	// This diverges from RFC 9420 §8.5 (which says "exporter") but matches mlspp and libdave behavior.
	exportedSecret, err := derivedSecret.KdfExpandLabel("exported", contextHash, length)
	if err != nil {
		return nil, fmt.Errorf("expand exported secret: %w", err)
	}

	return exportedSecret.AsSlice(), nil
}
