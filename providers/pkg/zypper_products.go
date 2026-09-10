package pkg

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

var errZypperProductsInvalidXML = errors.New("zypper: invalid products XML")

// zypperProductsOEMReadLimit bounds the OEM productline file read. Salt reads
// one line; anything beyond this size cannot be an OEM release marker.
const zypperProductsOEMReadLimit = 64 << 10

// zypperProductFrame tracks one open product element while the products XML
// streams past. endoflife and description state is filled by the first
// matching descendant in document order, mirroring minidom's
// getElementsByTagName over each product element.
type zypperProductFrame struct {
	order      int
	fields     map[string]any
	eolDone    bool
	eolText    string
	eolTimeRaw string
	descDone   bool
	descActive bool
	descDepth  int
	descParts  []string
}

func validateZypperProductsArgs(args map[string]any) error {
	keys := make([]string, 0, len(args))
	for key := range args {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key != "all" && key != "refresh" && key != "root" {
			return zypperUnsupportedArgument(key)
		}
	}
	if _, err := zypperBool(args, "all"); err != nil {
		return err
	}
	if _, err := zypperBool(args, "refresh"); err != nil {
		return err
	}
	_, err := zypperLowpkgRoot(args)
	return err
}

// zypperListProducts mirrors zypperpkg.list_products. The query keeps the
// pinned command order [--disable-repositories, products, -i] for installed
// products and a bare [products] when all is requested. OEM products override
// the release attribute from a bounded read of the productline file.
func zypperListProducts(ctx context.Context, rt *runtime.Runtime, args map[string]any) (any, error) {
	root, err := zypperLowpkgRoot(args)
	if err != nil {
		return nil, err
	}
	all := boolDefault(args, "all", false)

	if boolDefault(args, "refresh", false) {
		// list_products calls refresh_db(root) positionally: the supplied
		// root occupies refresh_db's force argument while refresh_db's own
		// root stays unset, so the refresh itself carries no --root. This
		// matches the committed list_patterns precedent for the same call
		// shape.
		refresh := []string{"refresh"}
		if zypperSearchRefreshForce(args) {
			refresh = append(refresh, "--force")
		}
		if _, err := zypperQueryRun(ctx, rt, "", false, true, refresh); err != nil {
			return nil, err
		}
	}

	query := []string{"products"}
	if !all {
		query = append([]string{"--disable-repositories"}, query...)
		query = append(query, "-i")
	}
	output, err := zypperQueryRun(ctx, rt, root, true, false, query)
	if err != nil {
		return nil, err
	}
	records, err := zypperParseProducts(ctx, output)
	if err != nil {
		return nil, err
	}

	oemBase := "/var/lib/suseRegister/OEM"
	if root != "" {
		oemBase = path.Join(root, "var/lib/suseRegister/OEM")
	}
	ret := make([]any, 0, len(records))
	for _, record := range records {
		product := record.fields
		if record.eolDone {
			timeT, err := zypperProductEOLTime(record.eolTimeRaw)
			if err != nil {
				return nil, err
			}
			product["eol"] = record.eolText
			product["eol_t"] = timeT
		}
		product["description"] = zypperProductDescription(record.descParts)
		productline, _ := product["productline"].(string)
		if zypperProductSafeProductline(productline) {
			release, ok, err := zypperProductOEMRelease(ctx, rt, path.Join(oemBase, productline))
			if err != nil {
				return nil, err
			}
			if ok {
				product["release"] = release
			}
		}
		ret = append(ret, product)
	}
	return ret, nil
}

// zypperProductEOLTime converts the endoflife time_t attribute with Python
// int() semantics; an absent or empty attribute is zero, like the source's
// int(value or 0). A malformed value is reported without echoing it.
func zypperProductEOLTime(raw string) (int64, error) {
	if raw == "" {
		return 0, nil
	}
	normalized, ok := zypperPythonIntDecimal(raw)
	if !ok {
		return 0, errors.New("zypper: invalid product endoflife time_t")
	}
	value, err := strconv.ParseInt(normalized, 10, 64)
	if err != nil {
		return 0, errors.New("zypper: invalid product endoflife time_t")
	}
	return value, nil
}

// zypperProductDescription reproduces _get_first_aggregate_text followed by
// the source's line split, per-line strip, and single-space join. The
// aggregate joins the first description element's direct text-node children
// with newlines; splitting on os.linesep (newline on the Linux minions this
// provider targets) then collapses every line into one space-separated
// string.
func zypperProductDescription(parts []string) string {
	lines := strings.Split(strings.Join(parts, "\n"), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
	}
	return strings.Join(lines, " ")
}

// zypperProductSafeProductline accepts plain file names only. Salt's
// os.path.join would let an absolute path or traversal component escape the
// OEM directory; the port keeps the bounded read inside it instead, which is
// observably identical to a missing OEM file.
func zypperProductSafeProductline(productline string) bool {
	if productline == "" || productline == "." || productline == ".." {
		return false
	}
	if strings.ContainsAny(productline, `/\`) {
		return false
	}
	return validZypperToken(productline, false)
}

// zypperProductOEMRelease reads the first line of the OEM productline file.
// Salt's os.path.isfile guard silently skips missing files; every other
// bounded-read failure is treated the same way so filesystem paths are never
// reflected in diagnostics. Only cancellation propagates.
func zypperProductOEMRelease(ctx context.Context, rt *runtime.Runtime, oemFile string) (string, bool, error) {
	if rt == nil || rt.FS == nil {
		return "", false, nil
	}
	data, err := runtime.ReadFileBounded(rt.FS, oemFile, zypperProductsOEMReadLimit)
	if err != nil {
		if ctxErr := contextErr(ctx); ctxErr != nil {
			return "", false, ctxErr
		}
		return "", false, nil
	}
	// Text-mode readline stops at the first of CR or LF.
	line := data
	if index := bytes.IndexAny(data, "\n\r"); index >= 0 {
		line = data[:index]
	}
	release := strings.TrimSpace(string(line))
	if release == "" || !validZypperToken(release, false) {
		return "", false, nil
	}
	return release, true, nil
}

// zypperParseProducts streams the zypper products XML. RawToken preserves the
// lexical element prefix, so only unprefixed product-list, product,
// endoflife, and description elements match, exactly like minidom's qualified
// getElementsByTagName lookups. Products collect in document order under the
// first product-list element; a second product-list is ignored because the
// source reads product_list[0] only. Nested products are separate results,
// and a nested product's endoflife or description also feeds any still-open
// outer product that has not found its own first match yet.
func zypperParseProducts(ctx context.Context, output string) ([]zypperProductFrame, error) {
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
	stack := make([]xml.Name, 0, 8)
	frames := make([]*zypperProductFrame, 0, 4)
	records := make([]zypperProductFrame, 0, 4)
	roots, elements, attributes, textNodes, products := 0, 0, 0, 0, 0
	productListDepth, productListDone := 0, false

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		token, err := decoder.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errZypperProductsInvalidXML
		}

		switch node := token.(type) {
		case xml.StartElement:
			if len(stack) == 0 {
				roots++
				if roots > 1 {
					return nil, errZypperProductsInvalidXML
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
			case !productListDone && productListDepth == 0 && unprefixed && node.Name.Local == "product-list":
				productListDepth = depth
			case productListDepth != 0 && depth > productListDepth && unprefixed && node.Name.Local == "product":
				products++
				if products > zypperLowpkgMaxItems {
					return nil, process.ErrOutputLimit
				}
				fields := make(map[string]any, len(node.Attr))
				for _, attr := range node.Attr {
					if attr.Name.Space != "" {
						// minidom exposes qualified attribute names; keep
						// them verbatim so they cannot collide with the
						// coerced isbase/installed keys.
						fields[attr.Name.Space+":"+attr.Name.Local] = attr.Value
						continue
					}
					switch attr.Name.Local {
					case "isbase", "installed":
						fields[attr.Name.Local] = attr.Value == "true" || attr.Value == "1"
					default:
						if attr.Value != "" {
							fields[attr.Name.Local] = attr.Value
						}
					}
				}
				frames = append(frames, &zypperProductFrame{fields: fields, order: products})
			case len(frames) > 0 && unprefixed && node.Name.Local == "endoflife":
				for _, frame := range frames {
					if frame.eolDone {
						continue
					}
					frame.eolDone = true
					for _, attr := range node.Attr {
						if attr.Name.Space != "" {
							continue
						}
						switch attr.Name.Local {
						case "text":
							frame.eolText = attr.Value
						case "time_t":
							frame.eolTimeRaw = attr.Value
						}
					}
				}
			case len(frames) > 0 && unprefixed && node.Name.Local == "description":
				for _, frame := range frames {
					if frame.descDone {
						continue
					}
					frame.descDone = true
					frame.descActive = true
					frame.descDepth = depth
				}
			}
			stack = append(stack, node.Name)

		case xml.CharData:
			if len(stack) == 0 && strings.TrimSpace(string(node)) != "" {
				return nil, errZypperProductsInvalidXML
			}
			// Only direct text children of a chosen description element
			// contribute to the aggregate; deeper character data belongs to
			// child elements. CDATA is indistinguishable from text with
			// RawToken, a documented minor divergence from minidom, which
			// excludes CDATA sections from TEXT_NODE aggregates.
			for _, frame := range frames {
				if !frame.descActive || frame.descDepth != len(stack) {
					continue
				}
				textNodes++
				if textNodes > zypperLowpkgMaxItems {
					return nil, process.ErrOutputLimit
				}
				frame.descParts = append(frame.descParts, string(node))
			}

		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1] != node.Name {
				return nil, errZypperProductsInvalidXML
			}
			depth := len(stack)
			switch {
			case productListDepth != 0 && depth == productListDepth && node.Name.Space == "" && node.Name.Local == "product-list":
				productListDepth = 0
				productListDone = true
			case node.Name.Space == "" && node.Name.Local == "product" && len(frames) > 0:
				// Well-formed nesting guarantees the closing product is the
				// innermost open frame; prefixed products never pushed one.
				frame := frames[len(frames)-1]
				frames = frames[:len(frames)-1]
				records = append(records, *frame)
			case node.Name.Space == "" && node.Name.Local == "description":
				for _, frame := range frames {
					if frame.descActive && frame.descDepth == depth {
						frame.descActive = false
					}
				}
			}
			stack = stack[:len(stack)-1]
		}
	}

	if roots != 1 || len(stack) != 0 {
		return nil, errZypperProductsInvalidXML
	}
	// Frames finalize when their element closes, so nested products append
	// before their parents. Restore minidom's document order with a stable
	// sort over the open-time sequence numbers.
	sort.SliceStable(records, func(i, j int) bool { return records[i].order < records[j].order })
	return records, nil
}
