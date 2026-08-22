// Package service implements Salt's virtual service-manager module concept.
//
// Reference: saltstack/salt/modules/systemd_service.py and
// debian_service/openrc siblings @ pinned revision. systemd is the primary
// provider; OpenRC covers Alpine and friends.
package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
)

// Provider is the virtual service interface consumed by exec and state modules.
type Provider interface {
	Name() string
	Start(ctx context.Context, rt *runtime.Runtime, name string) error
	Stop(ctx context.Context, rt *runtime.Runtime, name string) error
	Restart(ctx context.Context, rt *runtime.Runtime, name string) error
	Status(ctx context.Context, rt *runtime.Runtime, name string) (bool, error)
	Enabled(ctx context.Context, rt *runtime.Runtime, name string) (bool, error)
	Enable(ctx context.Context, rt *runtime.Runtime, name string) error
	Disable(ctx context.Context, rt *runtime.Runtime, name string) error
}

func runOK(ctx context.Context, rt *runtime.Runtime, argv []string) error {
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return res.Err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s exited with code %d: %s", argv[0], res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// systemctlProvider drives systemd via systemctl.
type systemctlProvider struct{}

func (systemctlProvider) Name() string { return "systemd" }

func (systemctlProvider) Start(ctx context.Context, rt *runtime.Runtime, name string) error {
	return runOK(ctx, rt, []string{"systemctl", "start", unit(name)})
}

func (systemctlProvider) Stop(ctx context.Context, rt *runtime.Runtime, name string) error {
	return runOK(ctx, rt, []string{"systemctl", "stop", unit(name)})
}

func (systemctlProvider) Restart(ctx context.Context, rt *runtime.Runtime, name string) error {
	return runOK(ctx, rt, []string{"systemctl", "restart", unit(name)})
}

func (systemctlProvider) Status(ctx context.Context, rt *runtime.Runtime, name string) (bool, error) {
	res := rt.Runner.Run(ctx, runtime.Command("systemctl", "is-active", "--quiet", unit(name)))
	if res.Err != nil {
		return false, res.Err
	}
	return res.ExitCode == 0, nil
}

func (systemctlProvider) Enabled(ctx context.Context, rt *runtime.Runtime, name string) (bool, error) {
	res := rt.Runner.Run(ctx, runtime.Command("systemctl", "is-enabled", "--quiet", unit(name)))
	if res.Err != nil {
		return false, res.Err
	}
	return res.ExitCode == 0, nil
}

func (systemctlProvider) Enable(ctx context.Context, rt *runtime.Runtime, name string) error {
	return runOK(ctx, rt, []string{"systemctl", "enable", unit(name)})
}

func (systemctlProvider) Disable(ctx context.Context, rt *runtime.Runtime, name string) error {
	return runOK(ctx, rt, []string{"systemctl", "disable", unit(name)})
}

// openrcProvider drives OpenRC via rc-service/rc-update.
type openrcProvider struct{}

func (openrcProvider) Name() string { return "openrc" }

func (openrcProvider) Start(ctx context.Context, rt *runtime.Runtime, name string) error {
	return runOK(ctx, rt, []string{"rc-service", name, "start"})
}

func (openrcProvider) Stop(ctx context.Context, rt *runtime.Runtime, name string) error {
	return runOK(ctx, rt, []string{"rc-service", name, "stop"})
}

func (openrcProvider) Restart(ctx context.Context, rt *runtime.Runtime, name string) error {
	return runOK(ctx, rt, []string{"rc-service", name, "restart"})
}

func (openrcProvider) Status(ctx context.Context, rt *runtime.Runtime, name string) (bool, error) {
	res := rt.Runner.Run(ctx, runtime.Command("rc-service", name, "status"))
	if res.Err != nil {
		return false, res.Err
	}
	return res.ExitCode == 0, nil
}

func (openrcProvider) Enabled(ctx context.Context, rt *runtime.Runtime, name string) (bool, error) {
	res := rt.Runner.Run(ctx, runtime.Command("rc-update", "show"))
	if res.Err != nil {
		return false, res.Err
	}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 1 && fields[0] == name {
			return true, nil
		}
	}
	return false, nil
}

func (openrcProvider) Enable(ctx context.Context, rt *runtime.Runtime, name string) error {
	return runOK(ctx, rt, []string{"rc-update", "add", name})
}

func (openrcProvider) Disable(ctx context.Context, rt *runtime.Runtime, name string) error {
	return runOK(ctx, rt, []string{"rc-update", "delete", name})
}

// unit appends .service for bare names, mirroring Salt's _systemctl_cmd.
func unit(name string) string {
	switch {
	case strings.Contains(name, "."):
		return name
	default:
		return name + ".service"
	}
}

// Select resolves the service provider from detected init system.
func Select(f *facts.Facts) (string, error) {
	switch f.InitSystem() {
	case "systemd":
		return "systemd", nil
	case "openrc":
		return "openrc", nil
	default:
		return "", fmt.Errorf("unsupported init system %q; only systemd and openrc are supported", f.InitSystem())
	}
}

// Register installs every service provider plus the fact-driven selector.
func Register(registry *runtime.ProviderRegistry) error {
	for _, p := range []Provider{systemctlProvider{}, openrcProvider{}} {
		if err := registry.Register("service", p.Name(), p); err != nil {
			return err
		}
	}
	registry.SetSelector("service", Select)
	return nil
}

// Resolve returns the active service provider for this host.
func Resolve(rt *runtime.Runtime) (Provider, error) {
	value, name, err := rt.Providers.Resolve(rt.Facts, "service")
	if err != nil {
		return nil, err
	}
	provider, ok := value.(Provider)
	if !ok {
		return nil, fmt.Errorf("provider %s does not implement service.Provider", name)
	}
	return provider, nil
}
