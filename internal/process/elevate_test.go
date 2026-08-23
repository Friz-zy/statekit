package process

import (
	"errors"
	"strings"
	"testing"
)

func TestElevatePrefersSudoThenDoas(t *testing.T) {
	orig := elevatorLookup
	defer func() { elevatorLookup = orig }()

	elevatorLookup = func(name string) (string, error) {
		if name == "sudo" {
			return "/usr/bin/sudo", nil
		}
		return "", execNotFound()
	}
	got, err := Elevate(Command{Name: "systemctl", Args: []string{"start", "x"}}, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "sudo" || strings.Join(got.Args, " ") != "systemctl start x" {
		t.Fatalf("sudo elevate wrong: %+v", got)
	}

	elevatorLookup = func(name string) (string, error) {
		if name == "doas" {
			return "/usr/bin/doas", nil
		}
		return "", execNotFound()
	}
	got, _ = Elevate(Command{Name: "pkg", Args: []string{"install", "-y", "curl"}}, "linux")
	if got.Name != "doas" || strings.Join(got.Args, " ") != "pkg install -y curl" {
		t.Fatalf("doas elevate wrong: %+v", got)
	}
}

func TestElevateShellWrapsWholeInvocation(t *testing.T) {
	orig := elevatorLookup
	defer func() { elevatorLookup = orig }()
	elevatorLookup = func(name string) (string, error) { return "/usr/bin/sudo", nil }

	got, err := Elevate(Command{Name: "echo secret > /root/f", Shell: true}, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if got.Shell {
		t.Fatal("elevated command must be direct argv")
	}
	if got.Name != "sudo" || strings.Join(got.Args, "|") != "-c|echo secret > /root/f" {
		t.Fatalf("shell elevate wrong: %+v", got)
	}
}

func TestElevateWithoutHelperFails(t *testing.T) {
	orig := elevatorLookup
	defer func() { elevatorLookup = orig }()
	elevatorLookup = func(string) (string, error) { return "", execNotFound() }

	if _, err := Elevate(Command{Name: "id"}, "linux"); !errors.Is(err, ErrNoElevationHelper) {
		t.Fatalf("expected ErrNoElevationHelper, got %v", err)
	}
}

func TestElevateWindowsContract(t *testing.T) {
	if _, err := Elevate(Command{Name: "whoami"}, "windows"); !errors.Is(err, ErrWindowsElevation) {
		t.Fatalf("windows contract error expected, got %v", err)
	}
}

func TestDetectUnixElevatorEmptyWhenAbsent(t *testing.T) {
	orig := elevatorLookup
	defer func() { elevatorLookup = orig }()
	elevatorLookup = func(string) (string, error) { return "", execNotFound() }
	if got := DetectUnixElevator(); got != "" {
		t.Fatalf("detector = %q", got)
	}
}

func execNotFound() error { return &notFoundErr{} }

type notFoundErr struct{}

func (*notFoundErr) Error() string { return "executable file not found in $PATH" }
