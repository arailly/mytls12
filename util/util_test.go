package util_test

import (
	"testing"

	"github.com/arailly/mytls12/util"
	"github.com/google/go-cmp/cmp"
)

func TestUint24(t *testing.T) {
	actual := util.ToBytes(util.NewUint24(uint32(1023)))
	expected := []byte{0, 3, 255}
	if diff := cmp.Diff(actual, expected); diff != "" {
		t.Errorf("bytes mismatch: %s", diff)
	}
}
