//go:build !windows

package process

import (
	"os/exec"
)

func configureWindowsCommandLine(_ *exec.Cmd, command Command) error {
	if command.WindowsCmdLine != "" {
		return ErrInvalidRabbitMQCommand
	}
	return nil
}

// RabbitMQCtlCommand resolves the canonical helper through PATH on Unix-like
// targets, matching Salt's non-Windows __virtual__ lookup.
func (DefaultRunner) RabbitMQCtlCommand() (string, bool) {
	path, err := exec.LookPath("rabbitmqctl")
	return path, err == nil
}

// RabbitMQPluginCommand mirrors Salt's __virtual__ PATH lookup.  The pinned
// module's _get_rabbitmq_plugin fallback is version-derived and therefore is
// resolved by the RabbitMQ module after pkg.version succeeds; this resolver
// must not guess by selecting an arbitrary glob match.
func (DefaultRunner) RabbitMQPluginCommand() (string, bool) {
	if path, err := exec.LookPath("rabbitmq-plugins"); err == nil {
		return path, true
	}
	return "", false
}

// RabbitMQPluginCommandRequiresPackage tells the module that a missing PATH
// helper may use Salt's exact pkg.version-derived package layout.  Keeping
// this capability separate lets hermetic fakes retain the canonical helper
// name without pretending that a package manager was queried.
func (DefaultRunner) RabbitMQPluginCommandRequiresPackage() bool { return true }
