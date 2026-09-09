package pkg

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	"gopkg.in/yaml.v3"
)

const zypperLocksFile = "/etc/zypp/locks"

var errZypperCleanLocksInvalidXML = errors.New("zypper: invalid clean locks XML")

// zypperOrderedMap is the serialization boundary for Python dict-shaped
// results whose insertion order is observable. A Go map can preserve the
// values but cannot retain first-insertion order when a key is overwritten.
// The JSON/YAML methods therefore emit an object from the ordered entries,
// keeping the public result shape without relying on map iteration.
type zypperOrderedMap struct {
	entries []zypperOrderedEntry
	index   map[string]int
}

type zypperOrderedEntry struct {
	key   string
	value any
}

func newZypperOrderedMap(capacity int) zypperOrderedMap {
	return zypperOrderedMap{
		entries: make([]zypperOrderedEntry, 0, capacity),
		index:   make(map[string]int, capacity),
	}
}

func (m *zypperOrderedMap) set(key string, value any) {
	if m.index == nil {
		m.index = map[string]int{}
	}
	if i, exists := m.index[key]; exists {
		m.entries[i].value = value
		return
	}
	m.index[key] = len(m.entries)
	m.entries = append(m.entries, zypperOrderedEntry{key: key, value: value})
}

func (m *zypperOrderedMap) delete(key string) {
	i, exists := m.index[key]
	if !exists {
		return
	}
	delete(m.index, key)
	m.entries = append(m.entries[:i], m.entries[i+1:]...)
	for j := i; j < len(m.entries); j++ {
		m.index[m.entries[j].key] = j
	}
}

func (m zypperOrderedMap) get(key string) (any, bool) {
	i, exists := m.index[key]
	if !exists {
		return nil, false
	}
	return m.entries[i].value, true
}

func (m zypperOrderedMap) asMap() map[string]any {
	out := make(map[string]any, len(m.entries))
	for _, entry := range m.entries {
		out[entry.key] = zypperOrderedValueAsMap(entry.value)
	}
	return out
}

func zypperOrderedValueAsMap(value any) any {
	switch value := value.(type) {
	case zypperOrderedMap:
		return value.asMap()
	case *zypperOrderedMap:
		if value == nil {
			return nil
		}
		return value.asMap()
	default:
		return value
	}
}

func (m zypperOrderedMap) MarshalJSON() ([]byte, error) {
	var out bytes.Buffer
	out.WriteByte('{')
	for i, entry := range m.entries {
		if i > 0 {
			out.WriteByte(',')
		}
		key, err := marshalZypperJSON(entry.key)
		if err != nil {
			return nil, err
		}
		value, err := marshalZypperJSON(entry.value)
		if err != nil {
			return nil, err
		}
		out.Write(key)
		out.WriteByte(':')
		out.Write(value)
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

func marshalZypperJSON(value any) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte{'\n'}), nil
}

func (m zypperOrderedMap) MarshalYAML() (any, error) {
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, entry := range m.entries {
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: entry.key}
		valueNode := &yaml.Node{}
		if err := valueNode.Encode(entry.value); err != nil {
			return nil, err
		}
		node.Content = append(node.Content, keyNode, valueNode)
	}
	return node, nil
}

func validateZypperLocksArgs(args map[string]any) error {
	keys := make([]string, 0, len(args))
	for key := range args {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key != "root" {
			return zypperUnsupportedArgument(key)
		}
	}
	_, err := zypperLocksRoot(args)
	return err
}

func zypperLocksRoot(args map[string]any) (string, error) {
	root, err := zypperLowpkgRoot(args)
	if err != nil {
		return "", err
	}
	if root == "" {
		return "", nil
	}
	// The lock path is joined below. Reject traversal components before the
	// join rather than relying on path.Clean, which would silently escape the
	// selected root. Backslash is rejected because zypper's target roots are
	// Unix paths and accepting it would make cross-platform validation
	// ambiguous.
	if strings.ContainsRune(root, '\\') {
		return "", zypperUnsupportedArgument("root")
	}
	for _, component := range strings.Split(root, "/") {
		if component == ".." {
			return "", zypperUnsupportedArgument("root")
		}
	}
	return root, nil
}

func zypperLocksPath(root string) string {
	if root == "" {
		return zypperLocksFile
	}
	return path.Join(root, strings.TrimPrefix(zypperLocksFile, "/"))
}

func zypperListLocks(ctx context.Context, rt *runtime.Runtime, args map[string]any) (zypperOrderedMap, error) {
	root, err := zypperLocksRoot(args)
	if err != nil {
		return zypperOrderedMap{}, err
	}
	if err := contextErr(ctx); err != nil {
		return zypperOrderedMap{}, err
	}
	ret := newZypperOrderedMap(0)
	if rt == nil || rt.FS == nil {
		return ret, nil
	}
	data, err := runtime.ReadFileBounded(rt.FS, zypperLocksPath(root), zypperLowpkgOutputLimit)
	if err != nil {
		if ctxErr := contextErr(ctx); ctxErr != nil {
			return zypperOrderedMap{}, ctxErr
		}
		// Salt treats a missing, unreadable, malformed, or otherwise
		// inaccessible lock file as an empty source-compatible result. The
		// underlying error is deliberately not returned because it contains
		// the selected filesystem path.
		return ret, nil
	}
	parsed, err := zypperParseLocks(ctx, string(data))
	if err != nil {
		if ctxErr := contextErr(ctx); ctxErr != nil {
			return zypperOrderedMap{}, ctxErr
		}
		return ret, nil
	}
	return parsed, nil
}

func zypperCleanLocks(ctx context.Context, rt *runtime.Runtime, args map[string]any) (map[string]any, error) {
	root, err := zypperLocksRoot(args)
	if err != nil {
		return nil, err
	}
	ret := map[string]any{"removed": 0}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if rt == nil || rt.FS == nil {
		return nil, errors.New("zypper clean_locks requires a filesystem")
	}

	// Read through the bounded no-follow capability solely to distinguish a
	// missing lock file from an existing one. No filesystem mutation is part of
	// this provider; the central zypper Runner is the only mutation boundary.
	_, err = runtime.ReadFileBounded(rt.FS, zypperLocksPath(root), zypperLowpkgOutputLimit)
	if ctxErr := contextErr(ctx); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ret, nil
		}
		return nil, errors.New("zypper clean_locks could not access the lock file")
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	output, err := zypperXMLMutationRun(ctx, rt, root, []string{"cl"})
	if err != nil {
		return nil, err
	}
	return zypperParseCleanLocks(ctx, output)
}

func zypperParseLocks(ctx context.Context, content string) (zypperOrderedMap, error) {
	if err := contextErr(ctx); err != nil {
		return zypperOrderedMap{}, err
	}
	if len(content) > zypperLowpkgOutputLimit {
		return zypperOrderedMap{}, process.ErrOutputLimit
	}
	// Python text-mode reads normalize LF, CRLF, and CR before split("\n\n").
	// Keep the raw bounded-read check above as the input-size boundary and only
	// normalize after it, so limits remain enforced on the received bytes.
	content = strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(content)
	blocks := strings.Split(content, "\n\n")
	if len(blocks) > zypperLowpkgMaxItems {
		return zypperOrderedMap{}, process.ErrOutputLimit
	}

	records := newZypperOrderedMap(len(blocks))
	linesSeen := 0
	for _, block := range blocks {
		if err := contextErr(ctx); err != nil {
			return zypperOrderedMap{}, err
		}
		fields := newZypperOrderedMap(0)
		for _, line := range strings.Split(block, "\n") {
			if line == "" {
				continue
			}
			linesSeen++
			if linesSeen > zypperLowpkgMaxItems {
				return zypperOrderedMap{}, process.ErrOutputLimit
			}
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			fields.set(strings.TrimSpace(key), strings.TrimSpace(value))
			if len(fields.entries) > zypperLowpkgMaxItems {
				return zypperOrderedMap{}, process.ErrOutputLimit
			}
		}
		nameValue, ok := fields.get("solvable_name")
		name, nameOK := nameValue.(string)
		if !ok || !nameOK || name == "" {
			continue
		}
		fields.delete("solvable_name")
		// set updates the value in place for an existing key, retaining its
		// first insertion position just like Python dict assignment.
		records.set(name, fields)
	}
	return records, nil
}

func zypperParseCleanLocks(ctx context.Context, output string) (map[string]any, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if len(output) > zypperLowpkgOutputLimit {
		return nil, process.ErrOutputLimit
	}

	ret := map[string]any{"removed": 0}
	decoder := xml.NewDecoder(strings.NewReader(output))
	stack := make([]xml.Name, 0, 8)
	type messageFrame struct {
		depth            int
		order            int
		firstChildSet    bool
		firstChildIsText bool
		firstChildText   string
	}
	messages := make([]messageFrame, 0, 4)
	completedMessages := make([]messageFrame, 0, 4)
	roots, elements, attributes := 0, 0, 0
	messageOrder := 0
	markFirstMessageChild := func(value string, isText bool) {
		if len(messages) == 0 || len(stack) != messages[len(messages)-1].depth {
			return
		}
		frame := &messages[len(messages)-1]
		if frame.firstChildSet {
			return
		}
		frame.firstChildSet = true
		frame.firstChildIsText = isText
		frame.firstChildText = value
	}

	for {
		if err := contextErr(ctx); err != nil {
			return nil, err
		}
		// RawToken preserves the lexical element name. The pinned minidom
		// getElementsByTagName("message") call matches the unprefixed
		// qualified name only, not every element whose local name is message.
		token, err := decoder.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errZypperCleanLocksInvalidXML
		}

		switch node := token.(type) {
		case xml.StartElement:
			// A child element is still the first DOM child. It must prevent a
			// later text node from being selected as the message payload.
			markFirstMessageChild("", false)
			if len(stack) == 0 {
				roots++
				if roots > 1 {
					return nil, errZypperCleanLocksInvalidXML
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
			for _, attr := range node.Attr {
				attributes++
				if attributes > zypperLowpkgMaxItems || len(attr.Value) > zypperLowpkgOutputLimit {
					return nil, process.ErrOutputLimit
				}
			}
			if node.Name.Space == "" && node.Name.Local == "message" {
				messages = append(messages, messageFrame{depth: depth, order: messageOrder})
				messageOrder++
				if messageOrder > zypperLowpkgMaxItems || len(messages) > zypperLowpkgMaxItems {
					return nil, process.ErrOutputLimit
				}
			}
			stack = append(stack, node.Name)

		case xml.CharData:
			if len(stack) == 0 && strings.TrimSpace(string(node)) != "" {
				return nil, errZypperCleanLocksInvalidXML
			}
			markFirstMessageChild(string(node), true)

		case xml.Comment:
			// minidom exposes comments through childNodes with nodeValue, so a
			// leading comment is semantically the first message value.
			markFirstMessageChild(string(node), true)

		case xml.ProcInst:
			// minidom exposes a processing instruction's data as nodeValue;
			// Target is not part of that value.
			markFirstMessageChild(string(node.Inst), true)

		case xml.Directive:
			markFirstMessageChild("", false)

		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1] != node.Name {
				return nil, errZypperCleanLocksInvalidXML
			}
			depth := len(stack)
			if len(messages) > 0 && messages[len(messages)-1].depth == depth {
				frame := messages[len(messages)-1]
				messages = messages[:len(messages)-1]
				completedMessages = append(completedMessages, frame)
			}
			stack = stack[:len(stack)-1]
		}
	}

	if roots != 1 || len(stack) != 0 || len(messages) != 0 {
		return nil, errZypperCleanLocksInvalidXML
	}
	sort.SliceStable(completedMessages, func(i, j int) bool {
		return completedMessages[i].order < completedMessages[j].order
	})
	found := false
	for _, frame := range completedMessages {
		if found {
			break
		}
		if !frame.firstChildSet || !frame.firstChildIsText {
			return nil, errZypperCleanLocksInvalidXML
		}
		lower := strings.ToLower(frame.firstChildText)
		if !strings.HasPrefix(lower, "removed") {
			continue
		}
		parts := strings.Split(lower, " ")
		if len(parts) < 2 {
			return nil, errZypperCleanLocksInvalidXML
		}
		ret["removed"] = parts[1]
		found = true
		break
	}
	return ret, nil
}
