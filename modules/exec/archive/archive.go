// Package archive implements Salt-compatible archiving functions using the
// Go standard library.
//
// Reference: saltstack/salt/modules/archive.py @ pinned revision. Supported
// subset: tar (create/extract/list, optional gzip via 'z' option), gzip,
// gunzip, zip, unzip.
package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

type tarArgs struct {
	Options string   `statekit:"name=options"`
	Tarfile string   `statekit:"required,name=tarfile"`
	Sources []string `statekit:"name=sources"`
	Dest    string   `statekit:"name=dest"`
	Cwd     string   `statekit:"name=cwd"`
}

type tarFunc struct{}

func (tarFunc) Name() string { return "archive.tar" }
func (tarFunc) Args() any    { return tarArgs{} }
func (tarFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*tarArgs)
	options := strings.ToLower(a.Options)
	compress := strings.ContainsAny(options, "zjJ")
	base := a.Cwd
	if base == "" {
		base = "/"
	}
	if strings.Contains(options, "x") {
		return extractTar(rt, expandPath(base, a.Tarfile), destDir(base, a.Dest))
	}
	if strings.Contains(options, "t") {
		return listTar(rt, expandPath(base, a.Tarfile))
	}
	if len(a.Sources) == 0 {
		return nil, fmt.Errorf("sources are required to create an archive")
	}
	return createTar(rt, expandPath(base, a.Tarfile), base, a.Sources, compress)
}

func destDir(base, dest string) string {
	if dest == "" {
		return base
	}
	if filepath.IsAbs(dest) {
		return dest
	}
	return filepath.Join(base, dest)
}

func expandPath(base, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}

func createTar(rt *runtime.Runtime, tarfile, cwd string, sources []string, gzipCompress bool) ([]string, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	added := []string{}
	for _, source := range sources {
		full := expandPath(cwd, source)
		info, err := rt.FS.Stat(full)
		if err != nil {
			return nil, fmt.Errorf("could not stat %q: %w", full, err)
		}
		name := strings.TrimPrefix(source, "./")
		if info.IsDir() {
			if err := addTreeToTar(rt, tw, full, cwd, &added); err != nil {
				return nil, err
			}
			continue
		}
		data, err := rt.FS.ReadFile(full)
		if err != nil {
			return nil, err
		}
		header := &tar.Header{
			Name: name,
			Mode: int64(info.Mode().Perm()),
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
		added = append(added, name)
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if gzipCompress {
		var gz bytes.Buffer
		writer := gzip.NewWriter(&gz)
		if _, err := writer.Write(out); err != nil {
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		out = gz.Bytes()
	}
	if err := rt.FS.WriteFile(tarfile, out, 0o644); err != nil {
		return nil, err
	}
	return added, nil
}

func addTreeToTar(rt *runtime.Runtime, tw *tar.Writer, dir, cwd string, added *[]string) error {
	entries, err := rt.FS.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		full := filepath.Join(dir, entry.Name())
		rel, relErr := filepath.Rel(cwd, full)
		if relErr != nil {
			rel = entry.Name()
		}
		if entry.IsDir() {
			if err := addTreeToTar(rt, tw, full, cwd, added); err != nil {
				return err
			}
			continue
		}
		data, err := rt.FS.ReadFile(full)
		if err != nil {
			return err
		}
		mode := fs.FileMode(0o644)
		if info, err := rt.FS.Stat(full); err == nil {
			mode = info.Mode().Perm()
		}
		header := &tar.Header{Name: rel, Mode: int64(mode.Perm()), Size: int64(len(data))}
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
		*added = append(*added, rel)
	}
	return nil
}

func openMaybeGzip(rt *runtime.Runtime, path string) ([]byte, bool, error) {
	data, err := rt.FS.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return data, false, nil
	}
	defer reader.Close()
	var out bytes.Buffer
	if _, err := out.ReadFrom(reader); err != nil {
		return nil, false, err
	}
	return out.Bytes(), true, nil
}

func extractTar(rt *runtime.Runtime, tarfile, dest string) ([]string, error) {
	raw, compressed, err := openMaybeGzip(rt, tarfile)
	if err != nil {
		return nil, err
	}
	_ = compressed
	tr := tar.NewReader(bytes.NewReader(raw))
	extracted := []string{}
	for {
		header, err := tr.Next()
		if err != nil {
			break
		}
		switch header.Typeflag {
		case tar.TypeReg:
			target := filepath.Join(dest, header.Name)
			if err := rt.FS.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return nil, err
			}
			content, err := readAll(tr)
			if err != nil {
				return nil, err
			}
			mode := fs.FileMode(header.Mode).Perm()
			if mode == 0 {
				mode = 0o644
			}
			if err := rt.FS.WriteFile(target, content, mode); err != nil {
				return nil, err
			}
			extracted = append(extracted, header.Name)
		case tar.TypeDir:
			if err := rt.FS.MkdirAll(filepath.Join(dest, header.Name), fs.FileMode(header.Mode).Perm()); err != nil {
				return nil, err
			}
		}
	}
	return extracted, nil
}

func listTar(rt *runtime.Runtime, tarfile string) ([]string, error) {
	raw, _, err := openMaybeGzip(rt, tarfile)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(bytes.NewReader(raw))
	names := []string{}
	for {
		header, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, header.Name)
	}
	return names, nil
}

func readAll(tr *tar.Reader) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(tr); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type gzipArgs struct {
	Sourcefile string `statekit:"required,name=sourcefile"`
	Options    string `statekit:"name=options"`
}

type gzipFunc struct{}

func (gzipFunc) Name() string { return "archive.gzip" }
func (gzipFunc) Args() any    { return gzipArgs{} }
func (gzipFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*gzipArgs)
	data, err := rt.FS.ReadFile(a.Sourcefile)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if err := rt.FS.WriteFile(a.Sourcefile+".gz", buf.Bytes(), 0o644); err != nil {
		return nil, err
	}
	return []string{a.Sourcefile + ".gz"}, nil
}

type gunzipArgs struct {
	Gzipfile string `statekit:"required,name=gzipfile"`
	Options  string `statekit:"name=options"`
	Runas    string `statekit:"name=runas"`
}

type gunzipFunc struct{}

func (gunzipFunc) Name() string { return "archive.gunzip" }
func (gunzipFunc) Args() any    { return gunzipArgs{} }
func (gunzipFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*gunzipArgs)
	data, _, err := openMaybeGzip(rt, a.Gzipfile)
	if err != nil {
		return nil, err
	}
	target := strings.TrimSuffix(a.Gzipfile, ".gz")
	if err := rt.FS.WriteFile(target, data, 0o644); err != nil {
		return nil, err
	}
	return []string{target}, nil
}

type zipArgs struct {
	ZipFile string   `statekit:"required,name=zip_file"`
	Sources []string `statekit:"required,name=sources"`
	Cwd     string   `statekit:"name=cwd"`
	Zip64   bool     `statekit:"name=zip64"`
}

type zipFunc struct{}

func (zipFunc) Name() string { return "archive.zip_" }
func (zipFunc) Args() any    { return zipArgs{} }
func (zipFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*zipArgs)
	base := a.Cwd
	if base == "" {
		base = "/"
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	added := []string{}
	for _, source := range a.Sources {
		full := expandPath(base, source)
		info, err := rt.FS.Stat(full)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			entries, err := rt.FS.ReadDir(full)
			if err != nil {
				return nil, err
			}
			for _, entry := range entries {
				child := filepath.Join(full, entry.Name())
				if err := addToZip(rt, zw, child, base, &added); err != nil {
					return nil, err
				}
			}
			continue
		}
		if err := addToZip(rt, zw, full, base, &added); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if err := rt.FS.WriteFile(a.ZipFile, buf.Bytes(), 0o644); err != nil {
		return nil, err
	}
	return added, nil
}

func addToZip(rt *runtime.Runtime, zw *zip.Writer, path, base string, added *[]string) error {
	data, err := rt.FS.ReadFile(path)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(base, path)
	if err != nil {
		rel = filepath.Base(path)
	}
	entry, err := zw.Create(rel)
	if err != nil {
		return err
	}
	if _, err := entry.Write(data); err != nil {
		return err
	}
	*added = append(*added, rel)
	return nil
}

type unzipArgs struct {
	ZipFile  string   `statekit:"required,name=zip_file"`
	Dest     string   `statekit:"name=dest"`
	Excludes []string `statekit:"name=excludes"`
}

type unzipFunc struct{}

func (unzipFunc) Name() string { return "archive.unzip" }
func (unzipFunc) Args() any    { return unzipArgs{} }
func (unzipFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*unzipArgs)
	dest := a.Dest
	if dest == "" {
		dest = "/"
	}
	data, err := rt.FS.ReadFile(a.ZipFile)
	if err != nil {
		return nil, err
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	extracted := []string{}
	for _, zf := range reader.File {
		if excluded(zf.Name, a.Excludes) {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, err
		}
		content, err := readAllBytes(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		target := filepath.Join(dest, zf.Name)
		if err := rt.FS.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return nil, err
		}
		mode := zf.Mode().Perm()
		if mode == 0 {
			mode = 0o644
		}
		if err := rt.FS.WriteFile(target, content, mode); err != nil {
			return nil, err
		}
		extracted = append(extracted, zf.Name)
	}
	return extracted, nil
}

func excluded(name string, excludes []string) bool {
	for _, pattern := range excludes {
		if ok, _ := filepath.Match(pattern, name); ok || strings.HasPrefix(name, pattern+"/") {
			return true
		}
	}
	return false
}

func readAllBytes(rc interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(rc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Register installs all archive-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{tarFunc{}, gzipFunc{}, gunzipFunc{}, zipFunc{}, unzipFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
