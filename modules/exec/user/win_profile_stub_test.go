//go:build !windows

package user

import (
	"context"
	"errors"
	"testing"
)

func TestWinProfileNonWindowsUnsupported(t *testing.T) {
	profile := ""
	res, err := (winChprofileFunc{}).Execute(context.Background(), nil, &winChprofileArgs{Name: "synthetic", Profile: &profile})
	if res != false || !errors.Is(err, errWinProfileUnsupported) || err.Error() != "profile operation unsupported" {
		t.Fatal("non-Windows factory did not fail closed")
	}
}
