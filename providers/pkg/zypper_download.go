package pkg

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

var (
	errZypperDownloadPackagesRequired = errors.New("No packages specified")
	errZypperDownloadInvalidXML       = errors.New("zypper: invalid download XML")
	errZypperDownloadIncompleteResult = errors.New("Zypper download: incomplete download-result")
	errZypperDownloadUnsafePath       = errors.New("Zypper download: invalid localfile path")
)

// validateZypperDownloadArgs mirrors download(*packages, refresh=False,
// root=None). Only the source-consumed kwargs are accepted.
func validateZypperDownloadArgs(args map[string]any) error {
	for key := range args {
		if key != "packages" && key != "refresh" && key != "root" {
			return zypperUnsupportedArgument(key)
		}
	}
	if _, err := zypperPackageList(args, "packages"); err != nil {
		return err
	}
	if _, err := zypperBool(args, "refresh"); err != nil {
		return err
	}
	_, err := zypperLowpkgRoot(args)
	return err
}

// zypperDownload ports zypperpkg.download. The XML `zypper download` output
// contributes one record per download-result element; each record's localfile
// is verified through the ported rpm_lowpkg.checksum before the entry joins
// the result. A partial result reports the missing packages through the
// source's "_error" key, while a fully empty result raises the ported
// CommandExecutionError.
func zypperDownload(ctx context.Context, rt *runtime.Runtime, args map[string]any) (any, error) {
	packages, err := zypperPackageList(args, "packages")
	if err != nil {
		return nil, err
	}
	if len(packages) == 0 {
		// SaltInvocationError boundary: raised before kwargs, refresh, or
		// zypper are touched.
		return nil, errZypperDownloadPackagesRequired
	}
	root, err := zypperLowpkgRoot(args)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if rt == nil || !pkgRunnerAvailable(rt.Runner) {
		return nil, errors.New("Zypper download requires a runner")
	}
	if rt.Options.Test {
		// Downloading populates the local package cache; preserve the
		// process-wide test mode boundary before any zypper or FS access.
		return map[string]any{}, nil
	}
	if rt.FS == nil {
		return nil, &runtime.UnsupportedError{Kind: "function", Name: "pkg.download filesystem"}
	}

	if boolDefault(args, "refresh", false) {
		// download calls refresh_db(root) positionally: the supplied root
		// occupies refresh_db's force argument while its own root stays
		// unset, matching the committed list_patterns precedent.
		refresh := []string{"refresh"}
		if zypperSearchRefreshForce(args) {
			refresh = append(refresh, "--force")
		}
		if _, err := zypperQueryRun(ctx, rt, "", false, true, refresh); err != nil {
			return nil, err
		}
	}

	output, err := zypperQueryRun(ctx, rt, root, true, false, append([]string{"download"}, packages...))
	if err != nil {
		return nil, err
	}
	results, err := zypperParseDownload(ctx, output)
	if err != nil {
		return nil, err
	}

	pkgRet := map[string]any{}
	for _, result := range results {
		if !result.haveRepository || !result.haveLocalfile {
			// repository[0]/localfile[0] on a missing element is an
			// IndexError in the pinned source; keep an explicit error
			// instead of choosing defaults.
			return nil, errZypperDownloadIncompleteResult
		}
		if err := validateZypperPath(result.localPath, false); err != nil {
			return nil, errZypperDownloadUnsafePath
		}
		checksum, err := zypperLowpkgChecksum(ctx, rt, result.localPath, root)
		if err != nil {
			return nil, err
		}
		// lowpkg.checksum returns a per-path mapping; the pinned source
		// tests the dict itself for truthiness, and a one-entry dict is
		// always truthy. Keep that exact contract: only a runner-level
		// failure can stop the record from joining the result.
		if len(checksum) > 0 {
			pkgRet[result.nameText] = map[string]any{
				"repository-name":  result.repositoryName,
				"repository-alias": result.repositoryAlias,
				"path":             result.localPath,
			}
		}
	}

	if len(pkgRet) > 0 {
		failed := make([]string, 0, len(packages))
		for _, pkg := range packages {
			if _, ok := pkgRet[pkg]; !ok {
				failed = append(failed, pkg)
			}
		}
		if len(failed) > 0 {
			pkgRet["_error"] = "The following package(s) failed to download: " + strings.Join(failed, ", ")
		}
		return pkgRet, nil
	}

	return nil, fmt.Errorf("Unable to download packages: %s", strings.Join(packages, ", "))
}

// zypperLowpkgChecksum ports rpm_lowpkg.checksum for one path: the value is
// file existence AND a zero `rpm -K --quiet` retcode, executed only when the
// file exists. A completed nonzero rpm result is a value, not an error; only
// runner failures, cancellation, and clipped streams propagate.
func zypperLowpkgChecksum(ctx context.Context, rt *runtime.Runtime, path, root string) (map[string]bool, error) {
	exists := rt != nil && rt.FS != nil
	if exists {
		_, statErr := rt.FS.Stat(path)
		exists = statErr == nil
	}
	if !exists {
		return map[string]bool{path: false}, nil
	}
	argv := []string{"rpm"}
	if root != "" {
		argv = append(argv, "--root", root)
	}
	argv = append(argv, "-K", "--quiet", path)
	result, err := zypperRPMRun(ctx, rt, argv, nil)
	if err != nil {
		return nil, err
	}
	return map[string]bool{path: result.ExitCode == 0}, nil
}

// zypperDownloadResultFrame tracks one open download-result element. The
// first repository, localfile, and name descendants in document order fill
// the record, mirroring minidom's getElementsByTagName(...)[0] lookups over
// each download-result element.
type zypperDownloadResultFrame struct {
	order           int
	repositoryName  string
	repositoryAlias string
	haveRepository  bool
	localPath       string
	haveLocalfile   bool
	nameDone        bool
	nameActive      bool
	nameDepth       int
	nameParts       []string
}

// zypperParseDownloadResult is the finalized record in document order.
type zypperParseDownloadResult struct {
	order           int
	repositoryName  string
	repositoryAlias string
	haveRepository  bool
	localPath       string
	haveLocalfile   bool
	nameText        string
}

func zypperParseDownload(ctx context.Context, output string) ([]zypperParseDownloadResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(output) > zypperLowpkgOutputLimit {
		return nil, process.ErrOutputLimit
	}

	decoder := xml.NewDecoder(strings.NewReader(output))
	stack := make([]xml.Name, 0, 4)
	frames := make([]*zypperDownloadResultFrame, 0, 2)
	records := make([]zypperParseDownloadResult, 0, 2)
	roots, elements, attributes, textNodes, results := 0, 0, 0, 0, 0

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		token, err := decoder.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errZypperDownloadInvalidXML
		}

		switch node := token.(type) {
		case xml.StartElement:
			if len(stack) == 0 {
				roots++
				if roots > 1 {
					return nil, errZypperDownloadInvalidXML
				}
			}
			depth := len(stack) + 1
			if depth > zypperSearchMaxXMLDepth {
				return nil, process.ErrOutputLimit
			}
			elements++
			if elements > zypperLowpkgMaxItems {
				return nil, process.ErrOutputLimit
			}
			attributeBytes := 0
			if len(node.Attr) > zypperPatternsMaxAttributesPerElement {
				return nil, process.ErrOutputLimit
			}
			for _, attr := range node.Attr {
				attributes++
				if attributes > zypperLowpkgMaxItems {
					return nil, process.ErrOutputLimit
				}
				attrBytes := len(attr.Name.Space) + len(attr.Name.Local) + len(attr.Value)
				if attrBytes > zypperPatternsMaxAttributeBytes || attributeBytes > zypperPatternsMaxAttributeBytes-attrBytes {
					return nil, process.ErrOutputLimit
				}
				attributeBytes += attrBytes
			}

			unprefixed := node.Name.Space == ""
			switch {
			case unprefixed && node.Name.Local == "download-result":
				results++
				if results > zypperLowpkgMaxItems {
					return nil, process.ErrOutputLimit
				}
				frames = append(frames, &zypperDownloadResultFrame{order: results})
			case len(frames) > 0 && unprefixed && node.Name.Local == "repository":
				for _, frame := range frames {
					if frame.haveRepository {
						continue
					}
					frame.haveRepository = true
					for _, attr := range node.Attr {
						if attr.Name.Space != "" {
							continue
						}
						switch attr.Name.Local {
						case "name":
							frame.repositoryName = attr.Value
						case "alias":
							frame.repositoryAlias = attr.Value
						}
					}
				}
			case len(frames) > 0 && unprefixed && node.Name.Local == "localfile":
				for _, frame := range frames {
					if frame.haveLocalfile {
						continue
					}
					frame.haveLocalfile = true
					for _, attr := range node.Attr {
						if attr.Name.Space == "" && attr.Name.Local == "path" {
							frame.localPath = attr.Value
						}
					}
				}
			case len(frames) > 0 && unprefixed && node.Name.Local == "name":
				for _, frame := range frames {
					if frame.nameDone {
						continue
					}
					frame.nameDone = true
					frame.nameActive = true
					frame.nameDepth = depth
				}
			}
			stack = append(stack, node.Name)

		case xml.CharData:
			if len(stack) == 0 && strings.TrimSpace(string(node)) != "" {
				return nil, errZypperDownloadInvalidXML
			}
			// Only direct text children of the chosen name element
			// contribute to _get_first_aggregate_text's "\n" join.
			for _, frame := range frames {
				if !frame.nameActive || frame.nameDepth != len(stack) {
					continue
				}
				textNodes++
				if textNodes > zypperLowpkgMaxItems {
					return nil, process.ErrOutputLimit
				}
				frame.nameParts = append(frame.nameParts, string(node))
			}

		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1] != node.Name {
				return nil, errZypperDownloadInvalidXML
			}
			if node.Name.Space == "" && node.Name.Local == "download-result" && len(frames) > 0 {
				frame := frames[len(frames)-1]
				frames = frames[:len(frames)-1]
				records = append(records, zypperParseDownloadResult{
					order:           frame.order,
					repositoryName:  frame.repositoryName,
					repositoryAlias: frame.repositoryAlias,
					haveRepository:  frame.haveRepository,
					localPath:       frame.localPath,
					haveLocalfile:   frame.haveLocalfile,
					nameText:        strings.Join(frame.nameParts, "\n"),
				})
			}
			if node.Name.Space == "" && node.Name.Local == "name" {
				for _, frame := range frames {
					if frame.nameActive && frame.nameDepth == len(stack) {
						frame.nameActive = false
					}
				}
			}
			stack = stack[:len(stack)-1]
		}
	}

	if roots != 1 || len(stack) != 0 {
		return nil, errZypperDownloadInvalidXML
	}
	// Frames finalize innermost-first; restore minidom document order with a
	// stable sort over the open-time sequence numbers.
	sort.SliceStable(records, func(i, j int) bool { return records[i].order < records[j].order })
	return records, nil
}
