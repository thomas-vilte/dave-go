package mediakeys

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

func TestExportWithMLSExporterSecretMatchesDiscordMLS(t *testing.T) {
	exporterSecret := ciphersuite.NewSecret([]byte{
		0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
		0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
	})
	ctx := SenderIDContextLE(0x0102030405060708)

	got, err := ExportWithMLSExporterSecret(exporterSecret, ciphersuite.MLS128DHKEMP256, ExporterLabel, ctx, BaseSecretLen)
	if err != nil {
		t.Fatalf("ExportWithMLSExporterSecret error: %v", err)
	}

	derivedSecret, err := exporterSecret.DeriveSecret(ciphersuite.MLS128DHKEMP256, ExporterLabel)
	if err != nil {
		t.Fatalf("DeriveSecret error: %v", err)
	}
	contextHash, err := ciphersuite.Hash(ciphersuite.MLS128DHKEMP256, ctx)
	if err != nil {
		t.Fatalf("Hash error: %v", err)
	}
	// Discord DAVE uses mlspp which uses "exported" (not "exporter") in ExpandWithLabel step 2.
	wantSecret, err := derivedSecret.KdfExpandLabel("exported", contextHash, BaseSecretLen)
	if err != nil {
		t.Fatalf("KdfExpandLabel error: %v", err)
	}
	want := wantSecret.AsSlice()

	if !bytes.Equal(got, want) {
		t.Fatalf("export mismatch:\n got  %x\n want %x", got, want)
	}
}

func TestExportWithMLSExporterSecretDiffersFromRFCExporter(t *testing.T) {
	// Discord DAVE uses mlspp, which uses "exported" in ExpandWithLabel step 2.
	// RFC 9420 §8.5 uses "exporter". These MUST produce different outputs —
	// confirming we match Discord/mlspp, not pure RFC.
	//
	// The RFC reference is computed by hand here rather than via
	// schedule.Exporter: as of mls-go v1.6.0 that function was aligned to mlspp
	// ("exported") for DAVE, so it can no longer stand in for the RFC "exporter"
	// derivation. dave-go's own derivation is unaffected — it hardcodes
	// "exported" — but the guard must reference the real RFC construction.
	exporterSecret := ciphersuite.NewSecret([]byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x55, 0xaa, 0x55, 0xaa, 0x12, 0x34, 0x56, 0x78,
		0x87, 0x65, 0x43, 0x21, 0x0f, 0xf0, 0x0f, 0xf0,
	})
	ctx := SenderIDContextLE(42)

	discordExport, err := ExportWithMLSExporterSecret(exporterSecret, ciphersuite.MLS128DHKEMP256, ExporterLabel, ctx, BaseSecretLen)
	if err != nil {
		t.Fatalf("ExportWithMLSExporterSecret error: %v", err)
	}

	// RFC 9420 §8.5: ExpandWithLabel(DeriveSecret(es, Label), "exporter", Hash(Context), Length).
	derivedSecret, err := exporterSecret.DeriveSecret(ciphersuite.MLS128DHKEMP256, ExporterLabel)
	if err != nil {
		t.Fatalf("DeriveSecret error: %v", err)
	}
	contextHash, err := ciphersuite.Hash(ciphersuite.MLS128DHKEMP256, ctx)
	if err != nil {
		t.Fatalf("Hash error: %v", err)
	}
	rfcSecret, err := derivedSecret.KdfExpandLabel("exporter", contextHash, BaseSecretLen)
	if err != nil {
		t.Fatalf("KdfExpandLabel error: %v", err)
	}
	rfcExport := rfcSecret.AsSlice()

	if bytes.Equal(discordExport, rfcExport) {
		t.Fatalf("ExportWithMLSExporterSecret (mlspp \"exported\") must NOT equal the RFC 9420 \"exporter\" derivation: both produced %x", discordExport)
	}
}
