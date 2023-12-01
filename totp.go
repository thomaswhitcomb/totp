package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"errors"
	"fmt"
	"time"
)

// TOTP is a time based one-time password.
type TOTP struct {
	secret []byte
	period int64
}

// New creates a TOTP based on the provided secret.
func New(secret string) (*TOTP, error) {
	if len(secret) < 16 {
		return nil, errors.New("secret must be equal to or longer than 16 bytes")
	}

	data, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}

	t := &TOTP{
		secret: data,
		period: 30,
	}

	return t, nil
}

// Code generates the one-time password. It returns the code and the time
// remaining (in seconds) that the code is still valid for.
func (t *TOTP) Code() (string, int64) {
	counter, remaining_time := counter_from_time(time.Now().Unix(), t.period)
	hash := generate_hash(t.secret, counter)
	chunk := chunk_from_hash(hash)
	code := code_from_chunk(chunk)
	return fmt.Sprintf("%06d", code), t.period - remaining_time
}

// convert the interval to base 256 and stick
// each number 0-ff in its own byte.
func interval_to_counter(num int64) []byte {
	bytes := make([]byte, 8)
	for i := 7; num > 0; i-- {
		rem := num % 256
		bytes[i] = byte(rem)
		num = num / 256
	}
	return bytes
}

// Create a SHA1 hash of the counter using the input secret
func generate_hash(secret []byte, counter []byte) []byte {
	mac := hmac.New(sha1.New, secret)
	mac.Write(counter)
	return mac.Sum(nil)
}

func code_from_chunk(chunk []byte) int {
	i, j := 0, 0
	shifts := []uint{24, 16, 8, 0}
	for k := 0; k < len(shifts); k++ {
		j = int(chunk[k])
		j = j << shifts[k]
		i = i | j
	}

	i = i % 1000000
	return i
}

func counter_from_time(unixtime int64, period int64) ([]byte, int64) {
	intervals := unixtime / period
	remaining_seconds := unixtime - (intervals * period)
	bytes := interval_to_counter(intervals)
	return bytes, remaining_seconds
}

func chunk_from_hash(hmac []byte) []byte {
	var b byte = hmac[len(hmac)-1]
	offset := int(b & 0x0F)
	chunk := hmac[offset:(offset + 4)]
	chunk[0] = chunk[0] & 0x7f
	return chunk
}
