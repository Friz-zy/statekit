package pam

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/runtime"
)

func TestReadFileParsesControlFlagGrammar(t *testing.T) {
	fs := runtime.NewMemoryFS()
	content := `# The pam_unix module handles auth
auth       required                        pam_env.so
auth       [success=1 default=ignore]      pam_unix.so nullok try_first_pass
account    required                        pam_unix.so
`
	if err := fs.MkdirAll("/etc/pam.d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/etc/pam.d/login", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	rt := &runtime.Runtime{FS: fs, Exec: runtime.NewExecRegistry(), States: runtime.NewStateRegistry()}
	res, err := readFileFunc{}.Execute(context.Background(), rt,
		&readFileArgs{FileName: "/etc/pam.d/login"})
	if err != nil {
		t.Fatal(err)
	}
	rules := res.([]map[string]any)
	if len(rules) != 3 {
		t.Fatalf("rules = %#v", rules)
	}

	bracketed := rules[1]
	if bracketed["control_flag"] != "success=1 default=ignore" {
		t.Fatalf("bracketed control_flag = %#v", bracketed["control_flag"])
	}
	if bracketed["module"] != "pam_unix.so" {
		t.Fatalf("bracketed module = %#v", bracketed["module"])
	}
	args, _ := bracketed["arguments"].([]string)
	if strings.Join(args, " ") != "nullok try_first_pass" {
		t.Fatalf("arguments = %#v", args)
	}

	simple := rules[0]
	if simple["interface"] != "auth" || simple["control_flag"] != "required" ||
		simple["module"] != "pam_env.so" || len(simple["arguments"].([]string)) != 0 {
		t.Fatalf("simple rule = %#v", simple)
	}
	last := rules[2]
	if last["interface"] != "account" || last["module"] != "pam_unix.so" {
		t.Fatalf("account rule = %#v", last)
	}

	// Missing file yields the literal False reply from upstream's _parse.
	res, err = readFileFunc{}.Execute(context.Background(), rt,
		&readFileArgs{FileName: "/etc/pam.d/absent"})
	if err != nil || res != false {
		t.Fatalf("missing-file reply = %#v, %v", res, err)
	}
}
