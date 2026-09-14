package facts

import (
	"reflect"
	"testing"
)

func TestParseSolarisUname(t *testing.T) {
	want := OSFacts{ID: FamilySolaris, Name: "Solaris", Family: FamilySolaris, Version: "5.11"}
	for _, out := range [][]byte{[]byte("SunOS 5.11\n"), []byte("SunOS\n5.11\n")} {
		if got := parseSolarisUname(out); !reflect.DeepEqual(got, want) {
			t.Fatalf("parseSolarisUname(%q)=%#v want=%#v", out, got, want)
		}
	}
	for _, out := range [][]byte{[]byte("Linux 6.1\n"), []byte("SunOS\n")} {
		if got := parseSolarisUname(out); !reflect.DeepEqual(got, OSFacts{}) {
			t.Fatalf("invalid Solaris probe %q=%#v", out, got)
		}
	}
}
