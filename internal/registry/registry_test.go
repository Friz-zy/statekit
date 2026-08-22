package registry

import "testing"

func TestRegisterGetNames(t *testing.T) {
	reg := New[string]()
	for _, name := range []string{"b.one", "a.two", "c.three"} {
		if err := reg.Register(name, name+"-value"); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
	}
	got, ok := reg.Get("a.two")
	if !ok || got != "a.two-value" {
		t.Fatalf("get returned %q ok=%v", got, ok)
	}
	if _, ok := reg.Get("missing"); ok {
		t.Fatal("unknown name must not resolve")
	}
	names := reg.Names()
	want := []string{"a.two", "b.one", "c.three"}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("names = %v, want %v", names, want)
		}
	}
	if reg.Len() != 3 {
		t.Fatalf("len = %d, want 3", reg.Len())
	}
}

func TestDuplicateRejected(t *testing.T) {
	reg := New[int]()
	if err := reg.Register("x", 1); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := reg.Register("x", 2); err == nil {
		t.Fatal("duplicate registration must fail")
	}
	if v, _ := reg.Get("x"); v != 1 {
		t.Fatalf("duplicate overwrote value: %d", v)
	}
}
