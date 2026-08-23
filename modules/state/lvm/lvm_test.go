package lvm

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
)

// stubFunc scripts lvm.* execution results like Salt's __salt__ mocks: the
// queued values are consumed in order and the last one repeats.
type stubFunc struct {
	name    string
	results []any
	calls   []any
}

func (s *stubFunc) Name() string { return s.name }
func (s *stubFunc) Args() any    { return struct{}{} }
func (s *stubFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	s.calls = append(s.calls, args)
	if len(s.results) == 0 {
		return nil, nil
	}
	next := s.results[0]
	if len(s.results) > 1 {
		s.results = s.results[1:]
	}
	return next, nil
}

func newRT(stubs ...*stubFunc) (*runtime.Runtime, []*stubFunc) {
	rt := &runtime.Runtime{
		Exec:      runtime.NewExecRegistry(),
		States:    runtime.NewStateRegistry(),
		Facts:     facts.ForTesting(facts.Overrides{}),
		Providers: runtime.NewProviderRegistry(),
		FS:        runtime.NewMemoryFS(),
	}
	for _, s := range stubs {
		if err := rt.Exec.Register(s); err != nil {
			panic(err)
		}
	}
	return rt, stubs
}

// lv01 mirrors the Salt fixture: a 2048 MB logical volume with 512 extents.
func lv01() map[string]any {
	return map[string]any{
		"/dev/testvg01/testlv01": map[string]any{
			"Logical Volume Name":                "/dev/testvg01/testlv01",
			"Volume Group Name":                  "testvg01",
			"Logical Volume Access":              "3",
			"Logical Volume Status":              "1",
			"Internal Logical Volume Number":     "-1",
			"Open Logical Volumes":               "0",
			"Logical Volume Size":                "4194304",
			"Current Logical Extents Associated": "512",
			"Allocated Logical Extents":          "-1",
			"Allocation Policy":                  "0",
			"Read Ahead Sectors":                 "-1",
			"Major Device Number":                "253",
			"Minor Device Number":                "9",
		},
	}
}

func emptyMap() map[string]any { return map[string]any{} }

func TestConvertToMB(t *testing.T) {
	valid := map[string]float64{
		"2048": 2048, "2048m": 2048, "2048M": 2048, "2048MB": 2048,
		"2g": 2048, "2G": 2048, "2GB": 2048,
		"4194304s": 2048, "4194304S": 2048,
		"3T": 3 * 1024 * 1024, "4P": 4 * 1024 * 1024 * 1024,
	}
	for in, want := range valid {
		got, err := convertToMB(in)
		if err != nil || got != want {
			t.Fatalf("convertToMB(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"1B", "1b", "2K", "2k", "2KB", "3BB", "4JKL", "YJK"} {
		if _, err := convertToMB(in); err == nil {
			t.Fatalf("convertToMB(%q) must fail", in)
		} else if msg := err.Error(); !strings.HasPrefix(msg, "Size "+in+" is invalid.") &&
			!strings.HasSuffix(msg, " is invalid.") {
			t.Fatalf("convertToMB(%q) message = %q", in, msg)
		}
	}
}

func TestPvPresent(t *testing.T) {
	present := &stubFunc{name: "lvm.pvdisplay",
		results: []any{map[string]any{"/dev/sda5": map[string]any{}}}}
	rt, _ := newRT(present)
	res := pvPresentFunc{}.Apply(context.Background(), rt, &pvPresentArgs{Name: "/dev/sda5"})
	if !res.Succeeded() || res.Changed() {
		t.Fatalf("already present = %+v", res)
	}
	if res.Comment != "Physical Volume /dev/sda5 already present" {
		t.Fatalf("comment = %q", res.Comment)
	}

	absent := &stubFunc{name: "lvm.pvdisplay", results: []any{emptyMap()}}
	rt2, _ := newRT(absent)
	res2 := pvPresentFunc{}.Apply(context.Background(), rt2, &pvPresentArgs{Name: "/dev/sda5", Test: true})
	if res2.Result != nil || res2.Changed() {
		t.Fatalf("test mode = %+v", res2)
	}
	if res2.Comment != "Physical Volume /dev/sda5 is set to be created" {
		t.Fatalf("pending comment = %q", res2.Comment)
	}

	create := &stubFunc{name: "lvm.pvcreate", results: []any{true}}
	disp := &stubFunc{name: "lvm.pvdisplay", results: []any{emptyMap(), map[string]any{
		"/dev/sda5": map[string]any{},
	}}}
	rt3, _ := newRT(create, disp)
	res3 := pvPresentFunc{}.Apply(context.Background(), rt3, &pvPresentArgs{Name: "/dev/sda5"})
	if !res3.Succeeded() || !res3.Changed() {
		t.Fatalf("created = %+v", res3)
	}
	if res3.Comment != "Created Physical Volume /dev/sda5" ||
		res3.Changes["created"] != true {
		t.Fatalf("created result = %+v", res3)
	}
	if len(create.calls) != 1 {
		t.Fatalf("pvcreate calls = %d", len(create.calls))
	}
}

func TestPvAbsent(t *testing.T) {
	absent := &stubFunc{name: "lvm.pvdisplay", results: []any{emptyMap()}}
	rt, _ := newRT(absent)
	res := pvAbsentFunc{}.Apply(context.Background(), rt, &pvAbsentArgs{Name: "/dev/sda5"})
	if !res.Succeeded() || res.Comment != "Physical Volume /dev/sda5 does not exist" {
		t.Fatalf("absent = %+v", res)
	}

	present := &stubFunc{name: "lvm.pvdisplay",
		results: []any{map[string]any{"/dev/sda5": map[string]any{}}}}
	rt2, _ := newRT(present)
	res2 := pvAbsentFunc{}.Apply(context.Background(), rt2, &pvAbsentArgs{Name: "/dev/sda5", Test: true})
	if res2.Result != nil || res2.Comment != "Physical Volume /dev/sda5 is set to be removed" {
		t.Fatalf("pending = %+v", res2)
	}
}

func TestVgPresent(t *testing.T) {
	noVG := &stubFunc{name: "lvm.vgdisplay", results: []any{emptyMap()}}
	failedCreate := &stubFunc{name: "lvm.vgcreate", results: []any{false}}
	rt, _ := newRT(noVG, failedCreate)
	res := vgPresentFunc{}.Apply(context.Background(), rt, &vgPresentArgs{Name: "testvg00"})
	if res.Succeeded() || res.Changed() {
		t.Fatalf("failed create = %+v", res)
	}
	if res.Comment != "Failed to create Volume Group testvg00" {
		t.Fatalf("comment = %q", res.Comment)
	}

	noVG2 := &stubFunc{name: "lvm.vgdisplay", results: []any{emptyMap()}}
	rt2, _ := newRT(noVG2)
	res2 := vgPresentFunc{}.Apply(context.Background(), rt2, &vgPresentArgs{Name: "testvg00", Test: true})
	if res2.Result != nil || res2.Comment != "Volume Group testvg00 is set to be created" {
		t.Fatalf("pending = %+v", res2)
	}

	// Orphan physical volume gets extended into the existing group.
	vgThere := &stubFunc{name: "lvm.vgdisplay",
		results: []any{map[string]any{"testvg": map[string]any{}}}}
	orphanPV := &stubFunc{name: "lvm.pvdisplay", results: []any{
		map[string]any{"/dev/sdb1": map[string]any{"Volume Group Name": ""}},
		map[string]any{"/dev/sdb1": map[string]any{"Volume Group Name": "testvg"}},
	}}
	extend := &stubFunc{name: "lvm.vgextend",
		results: []any{map[string]any{"Output from vgextend": "ok"}}}
	rt3, _ := newRT(vgThere, orphanPV, extend)
	res3 := vgPresentFunc{}.Apply(context.Background(), rt3, &vgPresentArgs{
		Name: "testvg", Devices: []string{"/dev/sdb1"},
	})
	if !res3.Succeeded() || !res3.Changed() {
		t.Fatalf("extend = %+v", res3)
	}
	if res3.Changes["/dev/sdb1"] != "added to testvg" {
		t.Fatalf("changes = %+v", res3.Changes)
	}
	if len(extend.calls) != 1 {
		t.Fatal("vgextend not invoked")
	}
}

func TestVgAbsent(t *testing.T) {
	noVG := &stubFunc{name: "lvm.vgdisplay", results: []any{emptyMap()}}
	rt, _ := newRT(noVG)
	res := vgAbsentFunc{}.Apply(context.Background(), rt, &vgAbsentArgs{Name: "testvg00"})
	if !res.Succeeded() || res.Comment != "Volume Group testvg00 already absent" {
		t.Fatalf("absent = %+v", res)
	}

	vgThere := &stubFunc{name: "lvm.vgdisplay",
		results: []any{map[string]any{"testvg00": map[string]any{}}}}
	rt2, _ := newRT(vgThere)
	res2 := vgAbsentFunc{}.Apply(context.Background(), rt2, &vgAbsentArgs{Name: "testvg00", Test: true})
	if res2.Result != nil || res2.Comment != "Volume Group testvg00 is set to be removed" {
		t.Fatalf("pending = %+v", res2)
	}
}

func TestLvPresent(t *testing.T) {
	lvThere := &stubFunc{name: "lvm.lvdisplay", results: []any{lv01()}}
	rt, _ := newRT(lvThere)
	res := lvPresentFunc{}.Apply(context.Background(), rt,
		&lvPresentArgs{Name: "testlv01", VGName: "testvg01"})
	if !res.Succeeded() || res.Changed() {
		t.Fatalf("already present = %+v", res)
	}
	if res.Comment != "Logical Volume testlv01 already present" {
		t.Fatalf("comment = %q", res.Comment)
	}

	lvMissing := &stubFunc{name: "lvm.lvdisplay", results: []any{emptyMap()}}
	rt2, _ := newRT(lvMissing)
	res2 := lvPresentFunc{}.Apply(context.Background(), rt2,
		&lvPresentArgs{Name: "testlv01", VGName: "testvg01", Test: true})
	if res2.Result != nil || res2.Comment != "Logical Volume testlv01 is set to be created" {
		t.Fatalf("pending = %+v", res2)
	}

	// Same requested size: no-op success.
	sameLV := &stubFunc{name: "lvm.lvdisplay", results: []any{lv01()}}
	rt3, _ := newRT(sameLV)
	res3 := lvPresentFunc{}.Apply(context.Background(), rt3,
		&lvPresentArgs{Name: "testlv01", VGName: "testvg01", Size: "2G"})
	if !res3.Succeeded() || res3.Comment != "Logical Volume testlv01 already present" {
		t.Fatalf("same size = %+v", res3)
	}

	// Growth in test mode pends a resize.
	growLV := &stubFunc{name: "lvm.lvdisplay", results: []any{lv01()}}
	rt4, _ := newRT(growLV)
	res4 := lvPresentFunc{}.Apply(context.Background(), rt4,
		&lvPresentArgs{Name: "testlv01", VGName: "testvg01", Size: "10G", Test: true})
	if res4.Result != nil || res4.Comment != "Logical Volume testlv01 is set to be resized" {
		t.Fatalf("grow pending = %+v", res4)
	}

	// Reduction requires force.
	reduceLV := &stubFunc{name: "lvm.lvdisplay", results: []any{lv01()}}
	rt5, _ := newRT(reduceLV)
	res5 := lvPresentFunc{}.Apply(context.Background(), rt5,
		&lvPresentArgs{Name: "testlv01", VGName: "testvg01", Size: "1G"})
	if res5.Succeeded() || res5.Comment != "To reduce a Logical Volume option 'force' must be True." {
		t.Fatalf("reduce = %+v", res5)
	}

	// Reduction with force in test mode still pends.
	forcedLV := &stubFunc{name: "lvm.lvdisplay", results: []any{lv01()}}
	rt6, _ := newRT(forcedLV)
	res6 := lvPresentFunc{}.Apply(context.Background(), rt6,
		&lvPresentArgs{Name: "testlv01", VGName: "testvg01", Size: "1G", Force: true, Test: true})
	if res6.Result != nil || res6.Comment != "Logical Volume testlv01 is set to be resized" {
		t.Fatalf("reduce pending = %+v", res6)
	}

	// Percentage extents never resize an existing volume.
	pctLV := &stubFunc{name: "lvm.lvdisplay", results: []any{lv01()}}
	rt7, _ := newRT(pctLV)
	res7 := lvPresentFunc{}.Apply(context.Background(), rt7,
		&lvPresentArgs{Name: "testlv01", VGName: "testvg01", Extents: "42%FREE"})
	if !res7.Succeeded() {
		t.Fatalf("percentage = %+v", res7)
	}
	want := "Logical Volume testlv01 already present, 42%FREE won't be resized."
	if res7.Comment != want {
		t.Fatalf("percentage comment = %q", res7.Comment)
	}

	// Invalid suffix fails the state with Salt's message.
	badLV := &stubFunc{name: "lvm.lvdisplay", results: []any{emptyMap()}}
	rt8, _ := newRT(badLV)
	res8 := lvPresentFunc{}.Apply(context.Background(), rt8,
		&lvPresentArgs{Name: "testlv01", VGName: "testvg01", Size: "1B"})
	if res8.Succeeded() || res8.Comment != "Size 1B is invalid." {
		t.Fatalf("invalid suffix = %+v", res8)
	}
}

func TestLvAbsent(t *testing.T) {
	noLV := &stubFunc{name: "lvm.lvdisplay", results: []any{emptyMap()}}
	rt, _ := newRT(noLV)
	res := lvAbsentFunc{}.Apply(context.Background(), rt,
		&lvAbsentArgs{Name: "testlv00", VGName: "testvg00"})
	if !res.Succeeded() || res.Comment != "Logical Volume testlv00 already absent" {
		t.Fatalf("absent = %+v", res)
	}

	lvThere := &stubFunc{name: "lvm.lvdisplay", results: []any{lv01()}}
	rt2, _ := newRT(lvThere)
	res2 := lvAbsentFunc{}.Apply(context.Background(), rt2,
		&lvAbsentArgs{Name: "testlv01", VGName: "testvg01", Test: true})
	if res2.Result != nil || res2.Comment != "Logical Volume testlv01 is set to be removed" {
		t.Fatalf("pending = %+v", res2)
	}
}

func TestPlatformConstraint(t *testing.T) {
	reg := runtime.NewStateRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	names := reg.Names()
	if len(names) != 6 {
		t.Fatalf("registered %d states", len(names))
	}
	for _, name := range names {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s lost", name)
		}
		if constrained, ok := fn.(interface{ Platforms() []string }); !ok ||
			strings.Join(constrained.Platforms(), ",") != "linux" {
			t.Fatalf("%s not linux-constrained", name)
		}
	}
}
