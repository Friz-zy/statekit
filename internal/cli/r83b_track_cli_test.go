package cli

import (
	"testing"

	"github.com/friz-zy/statekit/internal/runtime"
)

func TestR83bSolarisOnlyCLIExitThreeOnLinux(t *testing.T) {
	if runtime.CurrentGOOS() == "solaris" {
		t.Skip("Linux gating assertion does not apply on Solaris")
	}
	runner := &cliRecordingRunner{}
	app := solarisTrackCLIApp(t, runner)
	for _, name := range []string{
		"rbac.profile_list", "rbac.profile_get", "rbac.role_list", "rbac.auth_get",
		"service.get_running", "service.get_stopped", "service.get_all",
		"service.get_enabled", "service.get_disabled",
	} {
		code, _, errText := captureCode(t, app, "exec", name)
		if code != ExitUnsupported {
			t.Fatalf("%s code=%d err=%q, want exit 3", name, code, errText)
		}
	}
	if len(runner.calls) != 0 {
		t.Fatalf("Solaris-only CLI calls reached Runner: %#v", runner.calls)
	}
}
