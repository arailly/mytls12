package record

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestPHash(t *testing.T) {
	secret := []byte("secret")
	seed := []byte("seed")
	pHash := PHash(secret, seed, 64)

	a1 := HMACHash(secret, seed)
	expected1 := HMACHash(secret, append(a1, seed...))
	a2 := HMACHash(secret, a1)
	expected2 := HMACHash(secret, append(a2, seed...))
	expected := append(expected1, expected2...)

	actual := pHash[:len(expected)]
	if diff := cmp.Diff(expected, actual); diff != "" {
		t.Error(diff)
	}
}
