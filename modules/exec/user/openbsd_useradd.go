package user

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const (
	openBSDCommandTimeout = 10 * time.Second
	// Bound capture because userinfo may print encrypted password data.
	openBSDOutputLimit     = 64 << 10
	openBSDUserinfoCommand = "userinfo"
	openBSDUsermodCommand  = "usermod"
)

var (
	errOpenBSDInvalidArgs       = errors.New("invalid OpenBSD user arguments")
	errOpenBSDInvalidName       = errors.New("invalid username")
	errOpenBSDInvalidLoginclass = errors.New("invalid login class")
	errOpenBSDAlternateRoot     = errors.New("alternate roots are unsupported on OpenBSD")
	errOpenBSDRunnerUnavailable = errors.New("OpenBSD user command runner unavailable")
	errOpenBSDCommandFailed     = errors.New("OpenBSD user command failed")
)

func registerOpenBSDLoginclass(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{openBSDGetLoginclassFunc{}, openBSDChloginclassFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

type openBSDGetLoginclassArgs struct {
	Name string `statekit:"required"`
}

type openBSDGetLoginclassFunc struct{}

func (openBSDGetLoginclassFunc) Name() string        { return "user.get_loginclass" }
func (openBSDGetLoginclassFunc) Args() any           { return openBSDGetLoginclassArgs{} }
func (openBSDGetLoginclassFunc) Platforms() []string { return []string{"openbsd"} }
func (openBSDGetLoginclassFunc) Execute(ctx context.Context, rt *runtime.Runtime, raw any) (any, error) {
	a, ok := raw.(*openBSDGetLoginclassArgs)
	if !ok || a == nil {
		return nil, errOpenBSDInvalidArgs
	}
	class, err := openBSDGetLoginclass(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	return class, nil
}

type openBSDChloginclassArgs struct {
	Name       string  `statekit:"required"`
	Loginclass string  `statekit:"required,name=loginclass"`
	Root       *string `statekit:"name=root"`
}

type openBSDChloginclassFunc struct{}

func (openBSDChloginclassFunc) Name() string        { return "user.chloginclass" }
func (openBSDChloginclassFunc) Args() any           { return openBSDChloginclassArgs{} }
func (openBSDChloginclassFunc) Platforms() []string { return []string{"openbsd"} }
func (openBSDChloginclassFunc) Execute(ctx context.Context, rt *runtime.Runtime, raw any) (any, error) {
	a, ok := raw.(*openBSDChloginclassArgs)
	if !ok || a == nil {
		return nil, errOpenBSDInvalidArgs
	}
	if ctx == nil {
		return nil, errOpenBSDInvalidArgs
	}
	if err := openBSDValidateName(a.Name); err != nil {
		return nil, err
	}
	if a.Loginclass == "" {
		return nil, errOpenBSDInvalidLoginclass
	}
	if strings.IndexByte(a.Loginclass, 0) >= 0 {
		return nil, errOpenBSDInvalidLoginclass
	}
	if a.Root != nil {
		// OpenBSD userinfo/usermod have no alternate-root support; refusing root
		// avoids reading or verifying a different account database than intended.
		return nil, errOpenBSDAlternateRoot
	}
	if ctx.Err() != nil {
		return nil, errOpenBSDCommandFailed
	}
	if rt == nil || rt.Runner == nil {
		return nil, errOpenBSDRunnerUnavailable
	}

	current, err := openBSDGetLoginclass(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if current == a.Loginclass {
		return true, nil
	}
	if ctx.Err() != nil {
		return nil, errOpenBSDCommandFailed
	}
	if availability, ok := rt.Runner.(process.CommandAvailability); ok && !availability.CommandAvailable(openBSDUsermodCommand) {
		return nil, errOpenBSDRunnerUnavailable
	}
	if ctx.Err() != nil {
		return nil, errOpenBSDCommandFailed
	}

	cmd := openBSDCommand(openBSDUsermodCommand, "-L", a.Loginclass, a.Name)
	res := rt.Runner.Run(ctx, cmd)
	defer openBSDClearBytes(res.Stdout)
	defer openBSDClearBytes(res.Stderr)
	if res.Err != nil || ctx.Err() != nil || res.StdoutTruncated || res.StderrTruncated {
		return nil, errOpenBSDCommandFailed
	}
	// As with Salt's cmd.run result, a non-zero exit status is not itself a
	// Runner error; the verified post-state determines the returned boolean.
	post, err := openBSDGetLoginclass(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	return post == a.Loginclass, nil
}

func openBSDGetLoginclass(ctx context.Context, rt *runtime.Runtime, name string) (string, error) {
	if ctx == nil {
		return "", errOpenBSDInvalidArgs
	}
	if err := openBSDValidateName(name); err != nil {
		return "", err
	}
	if ctx.Err() != nil {
		return "", errOpenBSDCommandFailed
	}
	if rt == nil || rt.Runner == nil {
		return "", errOpenBSDRunnerUnavailable
	}
	cmd := openBSDCommand(openBSDUserinfoCommand, name)
	res := rt.Runner.Run(ctx, cmd)
	defer openBSDClearBytes(res.Stdout)
	defer openBSDClearBytes(res.Stderr)
	if res.Err != nil || ctx.Err() != nil || res.StdoutTruncated || res.StderrTruncated {
		return "", errOpenBSDCommandFailed
	}
	// userinfo can include the encrypted password field for privileged callers.
	// Parse bytes in place and retain only the copied class value; clearing the
	// returned buffers reduces exposure but is not guaranteed secure erasure.
	return openBSDLoginclassFromOutput(res.Stdout), nil
}

func openBSDCommand(argv ...string) process.Command {
	cmd := runtime.Command(argv...)
	cmd.Env = []string{"LC_ALL=C"}
	cmd.Timeout = openBSDCommandTimeout
	cmd.Shell = false
	cmd.MaxStdoutBytes = openBSDOutputLimit
	cmd.MaxStderrBytes = openBSDOutputLimit
	return cmd
}

func openBSDValidateName(name string) error {
	if name == "" || strings.HasPrefix(name, "-") {
		return errOpenBSDInvalidName
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return errOpenBSDInvalidName
		}
	}
	return nil
}

func openBSDClearBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func openBSDLoginclassFromOutput(output []byte) string {
	for start := 0; start < len(output); {
		end, next := openBSDLineBounds(output, start)
		line := output[start:end]
		if len(line) >= len("class") &&
			line[0] == 'c' && line[1] == 'l' && line[2] == 'a' && line[3] == 's' && line[4] == 's' {
			if class, ok := openBSDClassRemainder(line); ok {
				return class
			}
		}
		start = next
	}
	return ""
}

func openBSDClassRemainder(line []byte) (string, bool) {
	for i := 0; i < len(line); {
		r, size := utf8.DecodeRune(line[i:])
		if openBSDPythonSpace(r) {
			remainder := i + size
			for remainder < len(line) {
				r, size = utf8.DecodeRune(line[remainder:])
				if !openBSDPythonSpace(r) {
					break
				}
				remainder += size
			}
			if remainder == len(line) {
				return "", false
			}
			return string(line[remainder:]), true
		}
		i += size
	}
	return "", false
}

func openBSDPythonSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= '\u001c' && r <= '\u001f')
}

func openBSDLineBounds(data []byte, start int) (int, int) {
	for i := start; i < len(data); {
		switch data[i] {
		case '\n', '\v', '\f', '\x1c', '\x1d', '\x1e':
			return i, i + 1
		case '\r':
			if i+1 < len(data) && data[i+1] == '\n' {
				return i, i + 2
			}
			return i, i + 1
		}
		if i+1 < len(data) && data[i] == 0xc2 && data[i+1] == 0x85 {
			return i, i + 2
		}
		if i+2 < len(data) && data[i] == 0xe2 && data[i+1] == 0x80 && (data[i+2] == 0xa8 || data[i+2] == 0xa9) {
			return i, i + 3
		}
		_, size := utf8.DecodeRune(data[i:])
		i += size
	}
	return len(data), len(data)
}
