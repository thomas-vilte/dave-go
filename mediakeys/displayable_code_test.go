package mediakeys

import (
	"bytes"
	"strings"
	"testing"
)

func TestDisplayableCode_BasicVectors(t *testing.T) {
	cases := []struct {
		name      string
		secret    []byte
		codeLen   int
		groupSize int
		want      string
		wantErr   string
	}{
		{"all zeros → all zeros (5/5)", []byte{0, 0, 0, 0, 0}, 5, 5, "00000", ""},
		{"single 1 byte at end (5/5)", []byte{0, 0, 0, 0, 1}, 5, 5, "00001", ""},
		{
			"max 5-byte (5/5)",
			[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			5, 5,
			// 2^40 - 1 = 1099511627775; mod 10^5 = 27775
			"27775", "",
		},
		{
			"32-byte zeros → 30 zeros (epoch auth vector shape)", make([]byte, 32), 30, 5,
			strings.Repeat("0", 30), "",
		},
		{
			"32-byte max → 30 digits (6 groups, last 2 bytes unused)",
			bytes.Repeat([]byte{0xFF}, 32), 30, 5,
			// 6 groups of 0xFFFFFFFFFF (5 bytes) = 2^40 - 1 = 1099511627775;
			// (1099511627775 % 100000) = 27775 → "27775" × 6.
			strings.Repeat("27775", 6), "",
		},
		{
			"64-byte max → 45 digits (pairwise shape)",
			bytes.Repeat([]byte{0xFF}, 64), 45, 5,
			strings.Repeat("27775", 9), "",
		},

		// Error paths:
		{"group_size >= 8", []byte{1, 2, 3, 4, 5, 6, 7, 8}, 8, 8, "", "group size must be < 8"},
		{"group_size <= 0", []byte{1}, 1, 0, "", "group size must be > 0"},
		{"code_len not multiple of groupSize", []byte{1, 2, 3}, 4, 3, "", "multiple of group size"},
		{"input too short", []byte{1}, 5, 5, "", "input shorter than required"},

		// Multi-group non-trivial:
		{
			"2 groups: [0,0,0,0,1][0,0,0,0,2]",
			[]byte{0, 0, 0, 0, 1, 0, 0, 0, 0, 2},
			10, 5,
			"0000100002", "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DisplayableCode(tc.secret, tc.codeLen, tc.groupSize)
			switch {
			case tc.wantErr == "":
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if got != tc.want {
					t.Fatalf("got %q, want %q", got, tc.want)
				}
			case err == nil:
				t.Fatalf("want err containing %q, got nil", tc.wantErr)
			case !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("err = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}
