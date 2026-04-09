package frame

type Range struct {
	Offset int
	Length int
}

type EncryptParams struct {
	Plaintext         []byte
	Key               []byte
	TruncatedNonce    uint32
	UnencryptedRanges []Range
}

type DecryptParams struct {
	Ciphertext []byte
	Key        []byte
}

type ParsedFrame struct {
	InterleavedFrame  []byte
	Tag               []byte
	TruncatedNonce    uint32
	UnencryptedRanges []Range
	SupplementalSize  uint8
}
