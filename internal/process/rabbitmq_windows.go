//go:build windows

package process

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

const rabbitMQInstallRegistryPath = `SOFTWARE\VMware, Inc.\RabbitMQ Server`

func configureWindowsCommandLine(cmd *exec.Cmd, command Command) error {
	if command.WindowsCmdLine != "" {
		if command.Shell || command.Name != "cmd.exe" || len(command.Args) != 4 ||
			command.Args[0] != "/D" || command.Args[1] != "/S" || command.Args[2] != "/C" ||
			command.WindowsCmdLine != "cmd.exe /D /S /C "+command.Args[3] {
			return ErrInvalidRabbitMQCommand
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: command.WindowsCmdLine}
	}
	return nil
}

// rabbitMQWindowsCommands mirrors Salt's 32-bit-view registry lookup and
// last-ASCII-version selection without invoking cmd.exe or touching a broker.
func rabbitMQWindowsCommands() (ctl, plugins string, ok bool) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, rabbitMQInstallRegistryPath, registry.QUERY_VALUE|registry.WOW64_32KEY)
	if err != nil {
		return "", "", false
	}
	defer key.Close()
	installDir, valueType, err := key.GetStringValue("Install_Dir")
	if err != nil || valueType != registry.SZ {
		return "", "", false
	}
	if info, err := os.Stat(installDir); err != nil || !info.IsDir() {
		return "", "", false
	}
	entries, err := os.ReadDir(installDir)
	if err != nil {
		return "", "", false
	}
	selected := ""
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "rabbitmq_server-") {
			continue
		}
		candidate := filepath.Join(installDir, entry.Name())
		if candidate > selected {
			selected = candidate
		}
	}
	if selected == "" {
		return "", "", false
	}
	return filepath.Join(selected, "sbin", "rabbitmqctl.bat"), filepath.Join(selected, "sbin", "rabbitmq-plugins.bat"), true
}

func (DefaultRunner) RabbitMQCtlCommand() (string, bool) {
	ctl, _, ok := rabbitMQWindowsCommands()
	return ctl, ok
}

func (DefaultRunner) RabbitMQPluginCommand() (string, bool) {
	_, plugins, ok := rabbitMQWindowsCommands()
	return plugins, ok
}

func (DefaultRunner) RabbitMQPluginCommandRequiresPackage() bool { return false }
