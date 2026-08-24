package network

import (
	"strings"
	"testing"
)

func TestProbeParse(t *testing.T) {
	got, err := parseInterfacesIP(ipLinkOut)
	if len(got) == 0 {
		parts := strings.Split(ipLinkOut, "\n")
		for i, part := range parts {
			t.Logf("line %d: %q startsdigit=%v", i, part, len(part) > 0 && part[0] >= 48 && part[0] <= 57)
		}
	}
	t.Logf("err=%v n=%d", err, len(got))
	for name, entry := range got {
		m := entry.(map[string]any)
		t.Logf("%s keys=%v hwaddr=%v", name, len(m), m["hwaddr"])
	}
}
