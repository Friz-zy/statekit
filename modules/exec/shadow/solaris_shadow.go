package shadow

// Solaris virtual shadow implementation for Salt's solaris_shadow
// module (saltstack/salt/modules/solaris_shadow.py @ pinned revision
// 8b63e700637e, tests/pytests/unit/modules/test_solaris_shadow.py).
// The pinned module has two info() paths: the primary spwd branch and
// the SmartOS fallback that reads the password hash from /etc/shadow
// and the aging fields from `passwd -s name`. Go has no spwd
// equivalent behind the shell-free Runner, so StateKit ports the
// fallback path verbatim: the user lookup goes through `getent
// passwd`, the hash through the runtime FileSystem (/etc/shadow), and
// the aging fields through `passwd -s` parsing (columns: name, status,
// last-change, min, max, warn). Mutations run `passwd -x/-n/-w/-d` and
// set_password rewrites the /etc/shadow line, exactly like the source.
// The surface is untagged so the Linux test host can exercise every
// provider function directly with a recording fake Runner and a memory
// filesystem; Platforms() provides the solaris-only gating (mirroring
// Salt's __virtual__ kernel==SunOS check). shadow.Register selects this
// surface on a solaris GOOS. Official Go distributions list solaris/amd64
// and illumos/amd64 compile targets; this host has no native Solaris runtime
// runner, so the branch is exercised through registerSolaris directly.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func registerSolaris(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		sunDefaultHashFunc{}, sunInfoFunc{}, sunSetMaxdaysFunc{}, sunSetMindaysFunc{},
		sunGenPasswordFunc{}, sunDelPasswordFunc{}, sunSetPasswordFunc{}, sunSetWarndaysFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// sunShadowPath is the password database the fallback path reads.
const sunShadowPath = "/etc/shadow"

// sunRun is the bounded shell-free Runner bridge. Cancellation is checked
// before and after the Runner call; Runner errors (including a missing passwd
// binary) surface as errors, never as fabricated success.
func sunRun(ctx context.Context, rt *runtime.Runtime, argv ...string) (process.CommandResult, error) {
	if err := ctx.Err(); err != nil {
		return process.CommandResult{}, err
	}
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return res, res.Err
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	return res, nil
}

// sunRunStrict retains the historical helper name used by the mutators, but
// mirrors Salt's cmd.run default: completed non-zero exits are returned as
// command data and are not converted into errors. Only Runner failures and
// context cancellation are errors.
func sunRunStrict(ctx context.Context, rt *runtime.Runtime, argv ...string) (process.CommandResult, error) {
	res, err := sunRun(ctx, rt, argv...)
	if err != nil {
		return res, err
	}
	return res, nil
}

// sunEmptyInfo is the all-empty record shape returned for unknown
// users.
func sunEmptyInfo() map[string]any {
	return map[string]any{
		"name":   "",
		"passwd": "",
		"lstchg": "",
		"min":    "",
		"max":    "",
		"warn":   "",
		"inact":  "",
		"expire": "",
	}
}

// The info() dict carries dynamic value types after the passwd -s
// parse: lstchg string, min / max / warn int, inact / expire empty
// strings.

// sunDaysValue renders an aging field for string comparison with the
// caller-provided days argument.
func sunDaysValue(info map[string]any, key string) string {
	switch v := info[key].(type) {
	case int:
		return strconv.Itoa(v)
	case string:
		return v
	}
	return ""
}

// sunInfo ports the SmartOS fallback info(): pwd existence check via
// `getent passwd name`, hash from /etc/shadow, ages from `passwd -s`.
func sunInfo(ctx context.Context, rt *runtime.Runtime, name string) (map[string]any, error) {
	ret, _, err := sunInfoWithShadow(ctx, rt, name)
	return ret, err
}

// sunInfoWithShadow is sunInfo plus whether /etc/shadow was absent. A missing
// shadow file is the pinned source's empty/missing branch; every other read
// failure is returned without exposing a partial record or file contents.
func sunInfoWithShadow(ctx context.Context, rt *runtime.Runtime, name string) (map[string]any, bool, error) {
	ctx = sunCryptContext(ctx)
	ret := sunEmptyInfo()
	res, err := sunRun(ctx, rt, "getent", "passwd", name)
	if err != nil {
		return nil, false, err
	}
	if res.ExitCode != 0 {
		// pwd.getpwnam's KeyError path: the all-empty dict.
		return ret, false, nil
	}
	ret["name"] = name

	// Read the password hash from /etc/shadow when the file exists.
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	data, readErr := rt.FS.ReadFile(sunShadowPath)
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if readErr != nil {
		if errors.Is(readErr, fs.ErrNotExist) {
			return ret, true, nil
		}
		return nil, false, readErr
	}
	for _, line := range strings.Split(string(data), "\n") {
		comps := strings.Split(strings.TrimSpace(line), ":")
		if len(comps) >= 2 && comps[0] == name {
			ret["passwd"] = comps[1]
			break
		}
	}

	// Aging fields from `passwd -s name`; retcode is data, not failure.
	sres, err := sunRun(ctx, rt, "passwd", "-s", name)
	if err != nil {
		return nil, false, err
	}
	if sres.ExitCode != 0 {
		return ret, false, nil
	}
	fields := strings.Fields(string(sres.Stdout))
	if len(fields) == 2 {
		// For example "root      NL": no aging data.
		return ret, false, nil
	}
	if len(fields) < 6 {
		return nil, false, fmt.Errorf("passwd -s %s: unexpected column count %d", name, len(fields))
	}
	minDays, minErr := strconv.Atoi(fields[3])
	if minErr != nil {
		return nil, false, fmt.Errorf("passwd -s %s: invalid minimum age %q", name, fields[3])
	}
	maxDays, maxErr := strconv.Atoi(fields[4])
	if maxErr != nil {
		return nil, false, fmt.Errorf("passwd -s %s: invalid maximum age %q", name, fields[4])
	}
	warnDays, warnErr := strconv.Atoi(fields[5])
	if warnErr != nil {
		return nil, false, fmt.Errorf("passwd -s %s: invalid warning period %q", name, fields[5])
	}
	ret["lstchg"] = fields[2]
	ret["min"] = minDays
	ret["max"] = maxDays
	ret["warn"] = warnDays
	ret["inact"] = ""
	ret["expire"] = ""
	return ret, false, nil
}

// ---------------------------------------------------------------------------
// default_hash / info

type sunDefaultHashArgs struct{}

type sunDefaultHashFunc struct{}

func (sunDefaultHashFunc) Name() string        { return "shadow.default_hash" }
func (sunDefaultHashFunc) Args() any           { return sunDefaultHashArgs{} }
func (sunDefaultHashFunc) Platforms() []string { return []string{"solaris"} }
func (sunDefaultHashFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return "!", nil
}

type sunInfoArgs struct {
	Name string `statekit:"required"`
}

type sunInfoFunc struct{}

func (sunInfoFunc) Name() string        { return "shadow.info" }
func (sunInfoFunc) Args() any           { return sunInfoArgs{} }
func (sunInfoFunc) Platforms() []string { return []string{"solaris"} }
func (sunInfoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunInfoArgs)
	return sunInfo(ctx, rt, a.Name)
}

// ---------------------------------------------------------------------------
// age mutators (passwd -x / -n / -w)

type sunSetMaxdaysArgs struct {
	Name    string `statekit:"required"`
	Maxdays string `statekit:"required,name=maxdays"`
}

type sunSetMaxdaysFunc struct{}

func (sunSetMaxdaysFunc) Name() string        { return "shadow.set_maxdays" }
func (sunSetMaxdaysFunc) Args() any           { return sunSetMaxdaysArgs{} }
func (sunSetMaxdaysFunc) Platforms() []string { return []string{"solaris"} }
func (sunSetMaxdaysFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunSetMaxdaysArgs)
	pre, err := sunInfo(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if a.Maxdays == sunDaysValue(pre, "max") {
		return true, nil
	}
	if _, err := sunRunStrict(ctx, rt, "passwd", "-x", a.Maxdays, a.Name); err != nil {
		return nil, err
	}
	post, err := sunInfo(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if sunDaysValue(post, "max") != sunDaysValue(pre, "max") {
		return sunDaysValue(post, "max") == a.Maxdays, nil
	}
	// The pinned set_maxdays falls off the end here and returns None;
	// the nil result mirrors that contract.
	return nil, nil
}

type sunSetMindaysArgs struct {
	Name    string `statekit:"required"`
	Mindays string `statekit:"required,name=mindays"`
}

type sunSetMindaysFunc struct{}

func (sunSetMindaysFunc) Name() string        { return "shadow.set_mindays" }
func (sunSetMindaysFunc) Args() any           { return sunSetMindaysArgs{} }
func (sunSetMindaysFunc) Platforms() []string { return []string{"solaris"} }
func (sunSetMindaysFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunSetMindaysArgs)
	pre, err := sunInfo(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if a.Mindays == sunDaysValue(pre, "min") {
		return true, nil
	}
	if _, err := sunRunStrict(ctx, rt, "passwd", "-n", a.Mindays, a.Name); err != nil {
		return nil, err
	}
	post, err := sunInfo(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if sunDaysValue(post, "min") != sunDaysValue(pre, "min") {
		return sunDaysValue(post, "min") == a.Mindays, nil
	}
	return false, nil
}

type sunSetWarndaysArgs struct {
	Name     string `statekit:"required"`
	Warndays string `statekit:"required,name=warndays"`
}

type sunSetWarndaysFunc struct{}

func (sunSetWarndaysFunc) Name() string        { return "shadow.set_warndays" }
func (sunSetWarndaysFunc) Args() any           { return sunSetWarndaysArgs{} }
func (sunSetWarndaysFunc) Platforms() []string { return []string{"solaris"} }
func (sunSetWarndaysFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunSetWarndaysArgs)
	pre, err := sunInfo(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if a.Warndays == sunDaysValue(pre, "warn") {
		return true, nil
	}
	if _, err := sunRunStrict(ctx, rt, "passwd", "-w", a.Warndays, a.Name); err != nil {
		return nil, err
	}
	post, err := sunInfo(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if sunDaysValue(post, "warn") != sunDaysValue(pre, "warn") {
		return sunDaysValue(post, "warn") == a.Warndays, nil
	}
	return false, nil
}

// ---------------------------------------------------------------------------
// password mutators

type sunDelPasswordArgs struct {
	Name string `statekit:"required"`
}

type sunDelPasswordFunc struct{}

func (sunDelPasswordFunc) Name() string        { return "shadow.del_password" }
func (sunDelPasswordFunc) Args() any           { return sunDelPasswordArgs{} }
func (sunDelPasswordFunc) Platforms() []string { return []string{"solaris"} }
func (sunDelPasswordFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunDelPasswordArgs)
	if _, err := sunRunStrict(ctx, rt, "passwd", "-d", a.Name); err != nil {
		return nil, err
	}
	uinfo, shadowMissing, err := sunInfoWithShadow(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if shadowMissing {
		return false, nil
	}
	return uinfo["passwd"] == "", nil
}

type sunSetPasswordArgs struct {
	Name     string `statekit:"required"`
	Password string `statekit:"required"`
}

type sunSetPasswordFunc struct{}

func (sunSetPasswordFunc) Name() string        { return "shadow.set_password" }
func (sunSetPasswordFunc) Args() any           { return sunSetPasswordArgs{} }
func (sunSetPasswordFunc) Platforms() []string { return []string{"solaris"} }
func (sunSetPasswordFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunSetPasswordArgs)
	ctx = sunCryptContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := rt.FS.ReadFile(sunShadowPath)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		// The pinned source returns the empty dict without a shadow file.
		if errors.Is(err, fs.ErrNotExist) {
			return map[string]any{}, nil
		}
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		comps := strings.Split(strings.TrimSpace(line), ":")
		if len(comps) < 2 || comps[0] != a.Name {
			continue
		}
		comps[1] = a.Password
		lines[i] = strings.Join(comps, ":")
	}
	updated := []byte(strings.Join(lines, "\n"))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := rt.FS.WriteFile(sunShadowPath, updated, 0o400); err != nil {
		return nil, err
	}
	uinfo, shadowMissing, err := sunInfoWithShadow(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if shadowMissing {
		return false, nil
	}
	return uinfo["passwd"] == a.Password, nil
}

// ---------------------------------------------------------------------------
// gen_password (salt.utils.pycrypto.gen_hash crypt path)

type sunGenPasswordArgs struct {
	Password  string `statekit:"required"`
	CryptSalt string `statekit:"name=crypt_salt"`
	Algorithm string `statekit:"name=algorithm"`
}

type sunGenPasswordFunc struct{}

func (sunGenPasswordFunc) Name() string        { return "shadow.gen_password" }
func (sunGenPasswordFunc) Args() any           { return sunGenPasswordArgs{} }
func (sunGenPasswordFunc) Platforms() []string { return []string{"solaris"} }
func (sunGenPasswordFunc) Execute(ctx context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*sunGenPasswordArgs)
	algorithm := a.Algorithm
	if algorithm == "" {
		algorithm = "sha512"
	}
	return sunGenHashContext(ctx, a.Password, a.CryptSalt, algorithm)
}
