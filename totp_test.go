package totp

import (
	"bytes"
	"encoding/base32"
	"testing"
)

func TestCounterCreation(t *testing.T) {
	tests := []struct {
		name     string
		interval int64
		want     byte
	}{
		{"30", 30, 0x1e},
		{"255", 255, 0xff},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := interval_to_counter(tt.interval)
			if tt.want != got[7] {
				t.Errorf("want: %v, got %v", tt.want, got[7])
			}
		})
	}
}

func TestCounterCreation_1025(t *testing.T) {
	b := interval_to_counter(1025)
	if b[7] != 0x01 || b[6] != 0x04 {
		t.Error("Expected 0x04 and 0x01 but got:", b[7], b[6])
	}
}

func TestGenerateHash(t *testing.T) {
	secret, err := base32.StdEncoding.DecodeString("ABCDEFGHIJKLMNOP")
	if err != nil {
		t.Fatalf("want <nil, got %v", err)
	}

	b := interval_to_counter(1025)
	want := []byte{207, 6, 67, 115, 30, 56, 191, 55, 60, 97, 113, 240, 48, 124, 85, 120, 193, 99, 170, 82}
	got := generate_hash(secret, b)

	if !bytes.Equal(want, got) {
		t.Errorf("Bad hash, want: %v, got: %v", want, got)
	}
}

func TestCodeFromChunk(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want int
	}{
		{"rfc6238", []byte{9, 181, 88, 199}, 879687},
		{"rfc4226", []byte{0x50, 0xef, 0x7f, 0x19}, 872921},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := code_from_chunk(tt.data); tt.want != got {
				t.Errorf("Bad code chunk: want %v, got %v", tt.want, got)
			}
		})
	}
}

func TestChunkFromHash(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want []byte
	}{
		{
			"rfc6238",
			[]byte{237, 121, 86, 241, 173, 223, 106, 81, 252, 233, 111, 140, 26, 124, 77, 117, 209, 122, 142, 221},
			[]byte{124, 77, 117, 209},
		},
		{
			"rfc4226",
			[]byte{0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85, 0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e, 0x94, 0x5b, 0x55, 0x5a},
			[]byte{0x50, 0xef, 0x7f, 0x19},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := chunk_from_hash(tt.data)
			if !bytes.Equal(tt.want, got) {
				t.Errorf("Bad chunk from hash, want: %v, got %v", tt.want, got)
			}
		})
	}
}

func TestCounterFromTime(t *testing.T) {
	tests := []struct {
		name           string
		now            int64
		period         int64
		want_counter   []byte
		want_remaining int64
	}{
		{"time1", 0, 30, []byte{0, 0, 0, 0, 0, 0, 0, 0}, 0},
		{"time2", 1494368473, 30, []byte{0, 0, 0, 0, 2, 248, 19, 58}, 13},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotc, gotr := counter_from_time(tt.now, tt.period)
			if !bytes.Equal(tt.want_counter, gotc) {
				t.Errorf("Bad counter, want: %v, got: %v", tt.want_counter, gotc)
				return
			}
			if tt.want_remaining != gotr {
				t.Errorf("Bad remaining time, want: %v, got: %v", tt.want_remaining, gotr)
			}
		})
	}
}
