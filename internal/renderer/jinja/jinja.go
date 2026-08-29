// Package jinja is a deliberately small, process-isolated Jinja2 bridge.
// The supported subset is literals, variables, attribute/item lookup,
// conditionals, assignments, and (for load_map) the tojson filter. It is not
// full Salt/Jinja parity; loops, calls, loaders, imports, and expansion
// operators are intentionally excluded to keep evaluation bounded.
package jinja

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/friz-zy/statekit/internal/process"
)

const MaxBytes = 1 << 20
const bridgeStdoutBytes = 8*MaxBytes + 4096
const timeout = 2 * time.Second

var ErrJinjaUnavailable = errors.New("jinja: no usable Python interpreter with Jinja2")

type Request struct {
	Operation string
	Source    string
	Value     string
}

type response struct {
	Kind     string          `json:"kind"`
	Rendered json.RawMessage `json:"rendered"`
}

// The script is static: all untrusted values arrive as one JSON stdin object.
const bootstrap = `import io,json,sys
try:
    import jinja2
    from jinja2.sandbox import SandboxedEnvironment
except ModuleNotFoundError as e:
    if e.name == "jinja2":
        print(json.dumps({"kind":"missing_jinja2"}, separators=(",",":"))); sys.exit(0)
    print(json.dumps({"kind":"template_error"}, separators=(",",":"))); sys.exit(0)
try:
    r=json.load(sys.stdin)
    if not isinstance(r,dict) or r.get("protocol") != "statekit-jinja-v1" or r.get("operation") not in ("render","load_map") or not isinstance(r.get("source"),str) or not isinstance(r.get("value",""),str):
        print(json.dumps({"kind":"protocol_error"}, separators=(",",":"))); sys.exit(0)
    source=r["source"]
    if len(source.encode("utf-8")) > 1048576:
        print(json.dumps({"kind":"protocol_error"}, separators=(",",":"))); sys.exit(0)
    env=SandboxedEnvironment(undefined=jinja2.StrictUndefined, loader=None, autoescape=False)
    env.globals.clear()
    MAX_AST_NODES=4096
    MAX_AST_DEPTH=64
    MAX_LITERAL_BYTES=262144
    MAX_RENDER_BYTES=1048576
    MAX_RESPONSE_BYTES=8*1048576+4096
    allowed={"Template","Output","TemplateData","Name","Const","Getattr","Getitem","List","Dict","Pair","Tuple","CondExpr","Compare","Operand","And","Or","Not","Neg","Pos","Filter","Assign","If","ExprStmt"}
    forbidden={"Bin","Call","CallBlock","For","While","Import","FromImport","Include","Extends","Macro","Block","ScopedEvalContextModifier","EvalContextModifier","AssignBlock"}
    class TemplateRejected(Exception): pass
    class ResourceLimit(Exception): pass
    def validate(node, depth=0, state=None):
        if state is None: state={"count":0}
        if depth > MAX_AST_DEPTH:
            raise ResourceLimit()
        state["count"] += 1
        if state["count"] > MAX_AST_NODES:
            raise ResourceLimit()
        name=type(node).__name__
        if name in forbidden or name not in allowed:
            raise TemplateRejected()
        if name == "Name" and node.name == "range":
            raise TemplateRejected()
        if name == "Filter" and (r["operation"] != "load_map" or node.name != "tojson"):
            raise TemplateRejected()
        if name == "Const" and isinstance(node.value,str) and len(node.value.encode("utf-8")) > MAX_LITERAL_BYTES:
            raise ResourceLimit()
        if name == "Assign" and type(node.target).__name__ != "Name":
            raise TemplateRejected()
        for child in node.iter_child_nodes():
            validate(child, depth+1, state)
    def visible_output(node):
        if type(node).__name__ == "Output":
            for child in node.nodes:
                if type(child).__name__ != "TemplateData" or child.data.strip():
                    return True
        return any(visible_output(child) for child in node.iter_child_nodes())
    def write_bytes(writer, data):
        writer.write(data)
    def write_string(writer, value, rendered=False):
        if not isinstance(value,str): value=str(value)
        for char in value:
            if rendered:
                writer.rendered += len(char.encode("utf-8"))
                if writer.rendered > MAX_RENDER_BYTES: raise ResourceLimit()
            encoded=json.dumps(char, ensure_ascii=False)
            write_bytes(writer, encoded[1:-1].encode("utf-8"))
    def write_value(writer, value, depth=0):
        if depth > MAX_AST_DEPTH: raise ResourceLimit()
        if isinstance(value,dict):
            write_bytes(writer,b"{"); first=True
            for key,item in value.items():
                if not isinstance(key,str): raise TemplateRejected()
                if not first: write_bytes(writer,b",")
                first=False
                write_string(writer,key); write_bytes(writer,b":"); write_value(writer,item,depth+1)
            write_bytes(writer,b"}")
        elif isinstance(value,(list,tuple)):
            write_bytes(writer,b"[")
            for i,item in enumerate(value):
                if i: write_bytes(writer,b",")
                write_value(writer,item,depth+1)
            write_bytes(writer,b"]")
        elif isinstance(value,(str,int,float,bool)) or value is None:
            if isinstance(value,str): write_bytes(writer,b"\""); write_string(writer,value); write_bytes(writer,b"\"")
            else: write_bytes(writer,json.dumps(value,separators=(",",":"),allow_nan=False).encode("utf-8"))
        else: raise TemplateRejected()
    class ResponseWriter:
        def __init__(self): self.data=io.BytesIO(); self.rendered=0
        def write(self,data):
            if self.data.tell() + len(data) > MAX_RESPONSE_BYTES: raise ResourceLimit()
            self.data.write(data)
        def finish(self):
            sys.stdout.buffer.write(self.data.getvalue()); sys.stdout.buffer.flush()
    class EncodedValueWriter:
        def __init__(self,parent): self.parent=parent; self.value_bytes=0
        def write(self,data):
            self.value_bytes += len(data)
            if self.value_bytes > MAX_RENDER_BYTES: raise ResourceLimit()
            write_string(self.parent,data.decode("utf-8"))
    if r["operation"] == "load_map":
        value=r["value"]
        if len(value.encode("utf-8")) > 256 or not value or not (value[0].isalpha() or value[0] == "_") or not all(c.isalnum() or c == "_" for c in value):
            print(json.dumps({"kind":"protocol_error"}, separators=(",",":"))); sys.exit(0)
    ast=env.parse(source)
    validate(ast)
    template=env.from_string(source)
    writer=ResponseWriter()
    if r["operation"] == "load_map":
        if visible_output(ast): raise TemplateRejected()
        module=template.make_module()
        if not hasattr(module,value): raise jinja2.exceptions.UndefinedError(value)
        write_bytes(writer,b'{"kind":"ok","rendered":"')
        # The selected value is JSON, not a rendered template string.
        write_value(EncodedValueWriter(writer),getattr(module,value))
        write_bytes(writer,b'"}')
    else:
        write_bytes(writer,b'{"kind":"ok","rendered":"')
        for chunk in template.generate(): write_string(writer,chunk,True)
        write_bytes(writer,b'"}')
    writer.finish()
except ResourceLimit:
    sys.stdout.write('{"kind":"resource_limit"}')
    sys.stdout.flush()
except (TemplateRejected, jinja2.exceptions.TemplateError, MemoryError):
    print(json.dumps({"kind":"template_error"}, separators=(",",":")))
except Exception:
    print(json.dumps({"kind":"template_error"}, separators=(",",":")))
`

type resolver func(env []string, cwd string) []string

func productionResolver(env []string, cwd string) []string {
	lookup := exec.LookPath
	return resolveCandidates(env, cwd, lookup, runtime.GOOS)
}

func resolveCandidates(env []string, cwd string, lookup func(string) (string, error), goos string) []string {
	values := make(map[string]string)
	for _, item := range env {
		if k, v, ok := strings.Cut(item, "="); ok {
			values[k] = v
		}
	}
	seen := map[string]bool{}
	out := make([]string, 0, 6)
	add := func(candidate string) {
		if candidate == "" || !filepath.IsAbs(candidate) {
			return
		}
		candidate = filepath.Clean(candidate)
		canonical := candidate
		if absolute, err := filepath.Abs(candidate); err == nil {
			canonical = absolute
		}
		if resolved, err := filepath.EvalSymlinks(canonical); err == nil {
			canonical = resolved
		}
		if seen[canonical] {
			return
		}
		seen[canonical] = true
		if _, err := lookup(candidate); err == nil {
			out = append(out, candidate)
		}
	}
	if v := values["VIRTUAL_ENV"]; filepath.IsAbs(v) {
		if goos == "windows" {
			add(filepath.Join(v, "Scripts", "python.exe"))
		} else {
			add(filepath.Join(v, "bin", "python3"))
			add(filepath.Join(v, "bin", "python"))
		}
	}
	if filepath.IsAbs(cwd) {
		if goos == "windows" {
			add(filepath.Join(cwd, "venv", "Scripts", "python.exe"))
		} else {
			add(filepath.Join(cwd, "venv", "bin", "python3"))
			add(filepath.Join(cwd, "venv", "bin", "python"))
		}
	}
	for _, name := range []string{"python3", "python"} {
		if found, err := lookup(name); err == nil && filepath.IsAbs(found) {
			add(found)
		}
	}
	return out
}

// Render invokes the first usable candidate. A missing Jinja2 module advances
// to the next candidate; every other failure is terminal.
func Render(ctx context.Context, runner process.Runner, req Request) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !utf8.ValidString(req.Source) || len(req.Source) > MaxBytes {
		return "", errors.New("jinja: source exceeds 1 MiB or is not UTF-8")
	}
	if req.Operation != "render" && req.Operation != "load_map" {
		return "", errors.New("jinja: invalid operation")
	}
	if req.Operation == "load_map" && !validIdentifier(req.Value) {
		return "", errors.New("jinja: invalid load_map identifier")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", errors.New("jinja: cannot determine working directory")
	}
	env := os.Environ()
	return renderWithResolver(ctx, runner, req, productionResolver, env, cwd)
}

// renderWithResolver is private so production callers cannot select an
// executable, while same-package tests can supply deterministic candidates.
func renderWithResolver(ctx context.Context, runner process.Runner, req Request, resolve resolver, env []string, cwd string) (string, error) {
	return renderCandidates(ctx, runner, req, resolve(env, cwd), env, cwd)
}

func renderCandidates(ctx context.Context, runner process.Runner, req Request, candidates, env []string, cwd string) (string, error) {
	for _, candidate := range candidates {
		cleanEnv := scrubEnv(env)
		stdin, _ := json.Marshal(struct {
			Protocol  string `json:"protocol"`
			Operation string `json:"operation"`
			Source    string `json:"source"`
			Value     string `json:"value"`
		}{"statekit-jinja-v1", req.Operation, req.Source, req.Value})
		result := runner.Run(ctx, process.Command{Name: candidate, Args: []string{"-I", "-B", "-u", "-c", bootstrap, "statekit-jinja-v1"}, Dir: cwd, Env: cleanEnv, Stdin: stdin, Timeout: timeout, Shell: false, MaxStdoutBytes: bridgeStdoutBytes, MaxStderrBytes: MaxBytes})
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if result.Err != nil {
			if isMissingExecutable(result) {
				continue
			}
			return "", errors.New("jinja: Python bridge failed")
		}
		if result.ExitCode != 0 {
			return "", errors.New("jinja: Python bridge exited unsuccessfully")
		}
		if len(result.Stdout) == 0 || result.StdoutTruncated || result.StderrTruncated {
			return "", errors.New("jinja: invalid Python bridge response")
		}
		var response response
		if err := decodeOne(result.Stdout, &response); err != nil {
			return "", errors.New("jinja: invalid Python bridge response")
		}
		switch response.Kind {
		case "missing_jinja2":
			continue
		case "ok":
			var rendered string
			if len(response.Rendered) == 0 || string(response.Rendered) == "null" || json.Unmarshal(response.Rendered, &rendered) != nil {
				return "", errors.New("jinja: invalid Python bridge response")
			}
			if len(rendered) > MaxBytes || !utf8.ValidString(rendered) {
				return "", errors.New("jinja: rendered output exceeds 1 MiB")
			}
			return rendered, nil
		case "template_error":
			return "", errors.New("jinja: template error")
		case "resource_limit":
			return "", errors.New("jinja: template resource limit")
		case "protocol_error":
			return "", errors.New("jinja: protocol error")
		default:
			return "", errors.New("jinja: invalid Python bridge response")
		}
	}
	return "", ErrJinjaUnavailable
}

func scrubEnv(env []string) []string {
	out := make([]string, 0, len(env)+3)
	for _, item := range env {
		k, _, ok := strings.Cut(item, "=")
		if ok && !strings.HasPrefix(k, "PYTHON") {
			out = append(out, item)
		}
	}
	return append(out, "PYTHONNOUSERSITE=1", "PYTHONDONTWRITEBYTECODE=1", "PYTHONUTF8=1")
}

func decodeOne(data []byte, dst *response) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple responses")
		}
		return err
	}
	return nil
}
func validIdentifier(s string) bool {
	if len(s) == 0 || len(s) > 256 || !(s[0] == '_' || s[0] >= 'A' && s[0] <= 'Z' || s[0] >= 'a' && s[0] <= 'z') {
		return false
	}
	for _, c := range s[1:] {
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func isMissingExecutable(result process.CommandResult) bool {
	return result.ExitCode == -1 && errors.Is(result.Err, fs.ErrNotExist)
}
