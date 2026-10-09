package user

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"

	"github.com/friz-zy/statekit/internal/config"
)

type fakeWinProfileAPI struct {
	names, profiles []string
	ok              bool
	err             error
}

func (f *fakeWinProfileAPI) SetProfile(_ context.Context, name, profile string) (bool, error) {
	f.names = append(f.names, name)
	f.profiles = append(f.profiles, profile)
	return f.ok, f.err
}

func TestWinChprofileSemanticContract(t *testing.T) {
	for _, profile := range []string{`C:\Synthetic\😀`, `\\server\share\Synthetic`, ""} {
		f := &fakeWinProfileAPI{ok: true}
		res, err := (winChprofileFunc{api: f}).Execute(context.Background(), nil, &winChprofileArgs{Name: "synthetic", Profile: &profile})
		if err != nil || res != true || !reflect.DeepEqual(f.names, []string{"synthetic"}) || !reflect.DeepEqual(f.profiles, []string{profile}) {
			t.Fatal("semantic pass-through failed")
		}
	}
	f := &fakeWinProfileAPI{err: errWinProfileSet}
	profile := "synthetic"
	res, err := (winChprofileFunc{api: f}).Execute(context.Background(), nil, &winChprofileArgs{Name: "synthetic", Profile: &profile})
	if res != false || !errors.Is(err, errWinProfileSet) {
		t.Fatal("API failure claimed success")
	}
	f = &fakeWinProfileAPI{}
	res, err = (winChprofileFunc{api: f}).Execute(context.Background(), nil, &winChprofileArgs{Name: "synthetic", Profile: &profile})
	if res != false || err != nil {
		t.Fatal("bool result was inferred from error instead of propagated")
	}
	for _, args := range []any{nil, 7, (*winChprofileArgs)(nil), &winChprofileArgs{Name: "synthetic"}, &winChprofileArgs{Profile: &profile}} {
		f := &fakeWinProfileAPI{}
		res, err := (winChprofileFunc{api: f}).Execute(context.Background(), nil, args)
		if res != false || !errors.Is(err, errWinProfileInput) || len(f.names) != 0 {
			t.Fatal("invalid arguments reached semantic API")
		}
	}
	for _, name := range invalidProfileNames() {
		f := &fakeWinProfileAPI{}
		res, err := (winChprofileFunc{api: f}).Execute(context.Background(), nil, &winChprofileArgs{Name: name, Profile: &profile})
		if res != false || !errors.Is(err, errWinProfileInput) || len(f.names) != 0 {
			t.Fatal("invalid account name reached semantic API")
		}
	}
	fn := winChprofileFunc{}
	if fn.Name() != "user.chprofile" || !reflect.DeepEqual(fn.Platforms(), []string{"windows"}) {
		t.Fatal("metadata changed")
	}
	if _, ok := fn.Args().(winChprofileArgs); !ok {
		t.Fatal("argument contract changed")
	}
}

func TestWinChprofileRequiredProfilePresence(t *testing.T) {
	args := &winChprofileArgs{Name: "synthetic"}
	if config.ValidateRequired(args) == nil {
		t.Fatal("missing profile accepted by required validation")
	}
	profile := ""
	args.Profile = &profile
	if err := config.ValidateRequired(args); err != nil {
		t.Fatal("explicit empty profile rejected by required validation")
	}
}

type fakeRoleProbe struct {
	role      uint32
	status    uint32
	nilBuffer bool
}

type fakeProfileNetAPI struct {
	t *testing.T

	versionSupported bool
	name             string
	wantProfile      string
	accountProfile   string
	unrelatedField   uint32
	changeUnrelated  bool

	roleProbes    []fakeRoleProbe
	roleBuffers   map[unsafe.Pointer]int
	roleCalls     int
	roleFreeCalls int
	cancelOnRole  map[int]context.CancelFunc

	getStatus   uint32
	getNil      bool
	getCalls    int
	getFree     int
	getFreeCode uint32
	getBacking  []byte
	getOriginal []byte
	cancelGet   context.CancelFunc

	setStatus uint32
	setCalls  int
	cancelSet context.CancelFunc

	steps []string
}

func newFakeProfileNetAPI(t *testing.T) *fakeProfileNetAPI {
	t.Helper()
	backing := []byte{0xa5, 0x5a, 0x11, 0xee}
	return &fakeProfileNetAPI{
		t:                t,
		versionSupported: true,
		roleProbes:       []fakeRoleProbe{{role: testRoleStandaloneWorkstation}, {role: testRoleStandaloneWorkstation}},
		roleBuffers:      make(map[unsafe.Pointer]int),
		getBacking:       backing,
		getOriginal:      append([]byte(nil), backing...),
		cancelOnRole:     make(map[int]context.CancelFunc),
	}
}

func (f *fakeProfileNetAPI) SupportedWindowsVersion() bool {
	f.steps = append(f.steps, "version")
	return f.versionSupported
}

func (f *fakeProfileNetAPI) GetRoleInfo(server *uint16, level uint32) (unsafe.Pointer, uint32) {
	f.steps = append(f.steps, "role")
	f.roleCalls++
	if server != nil || level != 1 {
		f.t.Fatal("local DsRole primary-domain BASIC query contract")
	}
	probe := f.roleProbes[len(f.roleProbes)-1]
	if f.roleCalls <= len(f.roleProbes) {
		probe = f.roleProbes[f.roleCalls-1]
	}
	if f.changeUnrelated && f.roleCalls == 2 {
		f.unrelatedField++
	}
	if cancel := f.cancelOnRole[f.roleCalls]; cancel != nil {
		cancel()
	}
	if probe.nilBuffer {
		return nil, probe.status
	}
	role := new(winDSRolePrimaryDomainInfoBasic)
	role.MachineRole = probe.role
	owner := unsafe.Pointer(role)
	f.roleBuffers[owner] = 0
	return owner, probe.status
}

func (f *fakeProfileNetAPI) FreeRole(owner unsafe.Pointer) {
	f.steps = append(f.steps, "role-free")
	if owner == nil {
		f.t.Fatal("nil role allocation freed")
	}
	frees, ok := f.roleBuffers[owner]
	if !ok || frees != 0 {
		f.t.Fatal("role allocation not freed exactly once")
	}
	f.roleBuffers[owner] = 1
	f.roleFreeCalls++
}

func (f *fakeProfileNetAPI) GetInfo(server, name *uint16, level uint32) (unsafe.Pointer, uint32) {
	f.steps = append(f.steps, "get")
	f.getCalls++
	if server != nil || level != 0 || name == nil || f.roleFreeCalls != f.roleCalls {
		f.t.Fatal("NetUserGetInfo contract or role-buffer release ordering")
	}
	f.checkName(name)
	if f.cancelGet != nil {
		f.cancelGet()
	}
	if f.getNil {
		return nil, f.getStatus
	}
	return unsafe.Pointer(&f.getBacking[0]), f.getStatus
}

func (f *fakeProfileNetAPI) SetInfo(server, name *uint16, level uint32, owner unsafe.Pointer, parmErr *uint32) uint32 {
	f.steps = append(f.steps, "set")
	f.setCalls++
	if server != nil || level != 1052 || owner == nil || parmErr != nil || f.roleFreeCalls != f.roleCalls || f.getCalls != 0 {
		f.t.Fatal("profile-only NetUserSetInfo contract or role-buffer release ordering")
	}
	f.checkName(name)
	info := (*winUserInfo1052)(owner)
	if unsafe.Sizeof(*info) != unsafe.Sizeof(uintptr(0)) || unsafe.Offsetof(info.Profile) != 0 || info.Profile == nil {
		f.t.Fatal("submitted record was not USER_INFO_1052 with only Profile")
	}
	want := append(utf16.Encode([]rune(f.wantProfile)), 0)
	if got := unsafe.Slice(info.Profile, len(want)); !reflect.DeepEqual(got, want) {
		f.t.Fatal("profile UTF-16 input was not passed through exactly")
	}
	if f.setStatus == 0 {
		f.accountProfile = f.wantProfile
	}
	if f.cancelSet != nil {
		f.cancelSet()
	}
	return f.setStatus
}

func (f *fakeProfileNetAPI) Free(owner unsafe.Pointer) uint32 {
	f.steps = append(f.steps, "free")
	f.getFree++
	if f.getFree != 1 || owner != unsafe.Pointer(&f.getBacking[0]) {
		f.t.Fatal("account allocation was not freed exactly once with its base")
	}
	if !reflect.DeepEqual(f.getBacking, f.getOriginal) {
		f.t.Fatal("existence-only account buffer was modified or cleared")
	}
	return f.getFreeCode
}

func (f *fakeProfileNetAPI) checkName(name *uint16) {
	if name == nil {
		f.t.Fatal("nil account name")
	}
	want := append(utf16.Encode([]rune(f.name)), 0)
	if got := unsafe.Slice(name, len(want)); !reflect.DeepEqual(got, want) {
		f.t.Fatal("account name UTF-16 input was not passed through exactly")
	}
}

const (
	testRoleStandaloneWorkstation uint32 = iota
	testRoleMemberWorkstation
	testRoleStandaloneServer
	testRoleMemberServer
	testRoleBackupDomainController
	testRolePrimaryDomainController
)

func invalidProfileNames() []string {
	return []string{
		"",
		`DOMAIN\name`,
		`.\name`,
		"alice@example.invalid",
		"bad\x00name",
		string([]byte{0xff}),
		strings.Repeat("n", maxWinProfileUnits+1),
	}
}

func runProfileAPI(f *fakeProfileNetAPI, name, profile string) (bool, error) {
	f.name, f.wantProfile = name, profile
	return (netWinProfileAPI{api: f}).SetProfile(context.Background(), name, profile)
}

func assertRoleBuffersFreed(t *testing.T, f *fakeProfileNetAPI) {
	t.Helper()
	if f.roleFreeCalls != len(f.roleBuffers) {
		t.Fatalf("role buffers freed = %d, allocated = %d", f.roleFreeCalls, len(f.roleBuffers))
	}
	for _, frees := range f.roleBuffers {
		if frees != 1 {
			t.Fatal("non-nil role buffer was not freed exactly once")
		}
	}
}

func TestWinProfileVersionFloorFailsClosed(t *testing.T) {
	f := newFakeProfileNetAPI(t)
	f.versionSupported = false
	ok, err := runProfileAPI(f, "synthetic", "C:\\Profile")
	if ok || !errors.Is(err, errWinProfileUnsupported) || !reflect.DeepEqual(f.steps, []string{"version"}) {
		t.Fatal("unsupported or unverifiable Windows version reached native APIs")
	}
	if f.roleCalls+f.getCalls+f.setCalls != 0 {
		t.Fatal("unsupported Windows version dispatched a role or account API")
	}
}

func TestWinProfileRoleMatrix(t *testing.T) {
	for _, tc := range []struct {
		name string
		role uint32
	}{
		{"standalone workstation", testRoleStandaloneWorkstation},
		{"member workstation", testRoleMemberWorkstation},
		{"standalone server", testRoleStandaloneServer},
		{"member server", testRoleMemberServer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeProfileNetAPI(t)
			f.roleProbes = []fakeRoleProbe{{role: tc.role}, {role: tc.role}}
			ok, err := runProfileAPI(f, "synthetic", "C:\\Profile")
			if !ok || err != nil || f.roleCalls != 2 || f.getCalls != 0 || f.setCalls != 1 {
				t.Fatal("allowed local role did not perform one profile-only write")
			}
			if !reflect.DeepEqual(f.steps, []string{"version", "role", "role-free", "role", "role-free", "set"}) {
				t.Fatal("fresh role probes were not released before account mutation")
			}
			assertRoleBuffersFreed(t, f)
		})
	}

	for _, tc := range []struct {
		name  string
		probe fakeRoleProbe
	}{
		{"backup DC / RODC", fakeRoleProbe{role: testRoleBackupDomainController}},
		{"primary DC", fakeRoleProbe{role: testRolePrimaryDomainController}},
		{"unknown role", fakeRoleProbe{role: 99}},
		{"role probe failure with allocation", fakeRoleProbe{role: testRoleStandaloneWorkstation, status: 5}},
		{"role API unavailable", fakeRoleProbe{status: 127}},
		{"successful nil role buffer", fakeRoleProbe{role: testRoleStandaloneWorkstation, nilBuffer: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeProfileNetAPI(t)
			f.roleProbes = []fakeRoleProbe{tc.probe, {role: testRoleStandaloneWorkstation}}
			ok, err := runProfileAPI(f, "synthetic", "C:\\Profile")
			if ok || err == nil || f.roleCalls != 1 || f.getCalls+f.setCalls != 0 {
				t.Fatal("denied or unverifiable role reached an account API")
			}
			if strings.Contains(err.Error(), "synthetic") || strings.Contains(err.Error(), "127") || strings.Contains(err.Error(), "5") {
				t.Fatal("role error exposed account data or native status")
			}
			assertRoleBuffersFreed(t, f)
		})
	}
}

func TestWinProfileSecondRoleDenialPreventsWrite(t *testing.T) {
	f := newFakeProfileNetAPI(t)
	f.roleProbes = []fakeRoleProbe{
		{role: testRoleMemberServer},
		{role: testRoleBackupDomainController},
	}
	ok, err := runProfileAPI(f, "synthetic", "C:\\Profile")
	if ok || err == nil || f.roleCalls != 2 || f.getCalls != 0 || f.setCalls != 0 {
		t.Fatal("second denied role probe did not prevent the profile write")
	}
	if !reflect.DeepEqual(f.steps, []string{"version", "role", "role-free", "role", "role-free"}) {
		t.Fatal("second role allocation was not freed before denying mutation")
	}
	assertRoleBuffersFreed(t, f)
}

func TestWinProfileInvalidInputPrecedesEveryNativeDispatch(t *testing.T) {
	for _, name := range invalidProfileNames() {
		f := newFakeProfileNetAPI(t)
		ok, err := runProfileAPI(f, name, "C:\\Profile")
		if ok || !errors.Is(err, errWinProfileInput) || len(f.steps) != 0 {
			t.Fatal("invalid local account identifier reached native dispatch")
		}
	}
	for _, profile := range []string{"bad\x00path", string([]byte{0xff}), strings.Repeat("p", maxWinProfileUnits+1), strings.Repeat("😀", maxWinProfileUnits/2+1)} {
		f := newFakeProfileNetAPI(t)
		ok, err := runProfileAPI(f, "synthetic", profile)
		if ok || !errors.Is(err, errWinProfileInput) || len(f.steps) != 0 {
			t.Fatal("invalid profile value reached native dispatch")
		}
	}
}

func TestWinProfileUTF16PassThroughSameValueAndConcurrentUnrelatedChange(t *testing.T) {
	for _, profile := range []string{
		`C:\Synthetic\Profile`,
		`\\server\share\Synthetic\Profile`,
		`C:\Synthetic\😀\Profile`,
	} {
		t.Run(profile, func(t *testing.T) {
			f := newFakeProfileNetAPI(t)
			f.name = "synthetic"
			f.wantProfile = profile
			f.accountProfile = profile // Same-value input still must issue one write.
			f.unrelatedField = 7
			f.changeUnrelated = true // Simulate an unrelated account field changing before the write.
			ok, err := (netWinProfileAPI{api: f}).SetProfile(context.Background(), f.name, profile)
			if !ok || err != nil || f.setCalls != 1 || f.getCalls != 0 {
				t.Fatal("same-value profile did not issue exactly one level-1052 write")
			}
			if f.accountProfile != profile || f.unrelatedField != 8 {
				t.Fatal("write replayed a stale unrelated account-field snapshot")
			}
			if !reflect.DeepEqual(f.steps, []string{"version", "role", "role-free", "role", "role-free", "set"}) {
				t.Fatal("nonempty profile path performed a read, retry or extra API call")
			}
		})
	}
}

func TestWinProfileEmptyIsExistenceOnly(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     uint32
		nilBuffer  bool
		freeStatus uint32
		wantOK     bool
		wantErr    error
	}{
		{"exists", 0, false, 0, true, nil},
		{"missing", 2221, false, 0, false, errWinProfileMissing},
		{"error allocation", 5, false, 0, false, errWinProfileGet},
		{"success nil allocation", 0, true, 0, false, errWinProfileBuffer},
		{"error nil allocation", 5, true, 0, false, errWinProfileGet},
		{"cleanup failure after existence success", 0, false, 5, true, errWinProfileCleanupNoMutation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeProfileNetAPI(t)
			f.name = "synthetic"
			f.accountProfile = `C:\Before`
			f.getStatus, f.getNil, f.getFreeCode = tc.status, tc.nilBuffer, tc.freeStatus
			ok, err := (netWinProfileAPI{api: f}).SetProfile(context.Background(), f.name, "")
			if ok != tc.wantOK || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) || (tc.wantErr == nil && err != nil) {
				t.Fatal("empty profile existence semantics changed")
			}
			if f.getCalls != 1 || f.setCalls != 0 {
				t.Fatal("empty profile was not exactly one level-zero lookup and no write")
			}
			if f.accountProfile != `C:\Before` {
				t.Fatal("existence-only profile handling changed the profile")
			}
			wantSteps := []string{"version", "role", "role-free", "get"}
			if !tc.nilBuffer {
				wantSteps = append(wantSteps, "free")
			}
			if !reflect.DeepEqual(f.steps, wantSteps) {
				t.Fatal("existence lookup allocation cleanup order")
			}
			if f.getFree != 0 && f.getFree != 1 {
				t.Fatal("account allocation was freed more than once")
			}
			if tc.freeStatus != 0 && tc.wantOK && !errors.Is(err, errWinProfileCleanup) {
				t.Fatal("cleanup failure was not reported separately from completed existence success")
			}
			assertRoleBuffersFreed(t, f)
		})
	}
}

func TestWinProfileEmptyPrimaryAndCleanupErrorsArePreserved(t *testing.T) {
	f := newFakeProfileNetAPI(t)
	f.name = "synthetic"
	f.getStatus, f.getFreeCode = 5, 5
	ok, err := (netWinProfileAPI{api: f}).SetProfile(context.Background(), f.name, "")
	if ok || !errors.Is(err, errWinProfileGet) || !errors.Is(err, errWinProfileCleanup) {
		t.Fatal("lookup and allocation-cleanup failures were not both reported")
	}
	if f.getCalls != 1 || f.getFree != 1 || f.setCalls != 0 {
		t.Fatal("error allocation was not freed exactly once without a write")
	}
	assertRoleBuffersFreed(t, f)
}

func TestWinProfileWriteFailureDoesNotRetryOrRollback(t *testing.T) {
	f := newFakeProfileNetAPI(t)
	f.setStatus = 5
	ok, err := runProfileAPI(f, "synthetic", "C:\\Profile")
	if ok || !errors.Is(err, errWinProfileSet) || f.setCalls != 1 || f.getCalls != 0 {
		t.Fatal("failed write was retried, read back, or claimed successful")
	}
	if strings.Contains(err.Error(), "synthetic") || strings.Contains(err.Error(), "C:\\Profile") || strings.Contains(err.Error(), "5") {
		t.Fatal("write error exposed account data, profile value or native status")
	}
}

func TestWinProfileCancellationBoundaries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := newFakeProfileNetAPI(t)
	f.name, f.wantProfile = "synthetic", "C:\\Profile"
	if ok, err := (netWinProfileAPI{api: f}).SetProfile(ctx, f.name, f.wantProfile); ok || !errors.Is(err, context.Canceled) || len(f.steps) != 0 {
		t.Fatal("pre-canceled operation reached native dispatch")
	}

	for _, roleCall := range []int{1, 2} {
		ctx, cancel = context.WithCancel(context.Background())
		f = newFakeProfileNetAPI(t)
		f.name, f.wantProfile = "synthetic", "C:\\Profile"
		f.cancelOnRole[roleCall] = cancel
		ok, err := (netWinProfileAPI{api: f}).SetProfile(ctx, f.name, f.wantProfile)
		cancel()
		if ok || !errors.Is(err, context.Canceled) || f.setCalls != 0 {
			t.Fatal("cancellation during role probe did not prevent mutation")
		}
		if f.roleFreeCalls != f.roleCalls {
			t.Fatal("cancellation leaked role information buffer")
		}
	}

	ctx, cancel = context.WithCancel(context.Background())
	f = newFakeProfileNetAPI(t)
	f.name, f.cancelGet = "synthetic", cancel
	ok, err := (netWinProfileAPI{api: f}).SetProfile(ctx, f.name, "")
	cancel()
	if ok || !errors.Is(err, context.Canceled) || f.getCalls != 1 || f.getFree != 1 || f.setCalls != 0 {
		t.Fatal("cancellation during existence lookup did not retain cleanup semantics")
	}

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	f = newFakeProfileNetAPI(t)
	f.name, f.wantProfile, f.cancelSet = "synthetic", "C:\\Profile", cancel
	ok, err = (netWinProfileAPI{api: f}).SetProfile(ctx, f.name, f.wantProfile)
	if !ok || err != nil || ctx.Err() == nil || f.setCalls != 1 {
		t.Fatal("late cancellation relabeled confirmed synchronous SetInfo success")
	}
}

func TestWinProfileUTF16BoundsExcludeTerminator(t *testing.T) {
	for _, value := range []string{strings.Repeat("x", maxWinProfileUnits), strings.Repeat("😀", maxWinProfileUnits/2) + "x"} {
		units, err := profileUTF16(value)
		if err != nil || len(units) != maxWinProfileUnits+1 || units[len(units)-1] != 0 {
			t.Fatal("UTF-16 boundary excluding terminator changed")
		}
		f := newFakeProfileNetAPI(t)
		ok, err := runProfileAPI(f, "synthetic", value)
		if !ok || err != nil || f.setCalls != 1 || f.getCalls != 0 {
			t.Fatal("maximum valid UTF-16 profile did not pass through one write")
		}
	}
}
