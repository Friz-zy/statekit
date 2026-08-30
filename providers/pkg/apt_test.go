package pkg

import "testing"

func TestAPTNameAndArchitectureHelpers(t *testing.T) {
	for _, tc := range []struct {
		in, arch, name string
		parsed         map[string]any
	}{
		{"zsh:amd64", "amd64", "zsh", map[string]any{"name": "zsh", "arch": "amd64"}},
		{"zsh:i386", "amd64", "zsh:i386", map[string]any{"name": "zsh", "arch": "i386"}},
		{"zsh", "amd64", "zsh", map[string]any{"name": "zsh", "arch": nil}},
	} {
		if got := normalizeName(tc.in, tc.arch); got != tc.name {
			t.Errorf("normalizeName(%q)=%q", tc.in, got)
		}
		got := parseArch(tc.in)
		if got["name"] != tc.parsed["name"] || got["arch"] != tc.parsed["arch"] {
			t.Errorf("parseArch(%q)=%v", tc.in, got)
		}
	}
}

func TestDebianVersionOrdering(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0~rc1", "1.0", -1}, {"1:1.0", "2.0", 1},
		{"1.0-1", "1.0-2", -1}, {"1.0+really", "1.0~really", 1},
		{"1.0-1", "1.0-1", 0}, {"1.0-1", "1.0-1~bpo", 1},
	} {
		if got := debVersionCmp(tc.a, tc.b, false); got != tc.want {
			t.Errorf("compare %q %q=%d want %d", tc.a, tc.b, got, tc.want)
		}
	}
	if debVersionCmp("9:1", "2:9", true) >= 0 {
		t.Error("ignore_epoch must remove epochs")
	}
}
