//go:build !windows

package user

import "context"

type unsupportedWinProfileAPI struct{}

func newWinProfileAPI() winProfileAPI { return unsupportedWinProfileAPI{} }
func (unsupportedWinProfileAPI) SetProfile(context.Context, string, string) (bool, error) {
	return false, errWinProfileUnsupported
}
