// Package result defines the Salt-compatible state return contract.
//
// Reference: plans/init.md sections 9-10; saltstack/salt/states/test.py.
package result

// Bool returns a pointer to b, for building tri-state Result values
// (true / false / nil matching Salt's result semantics).
func Bool(b bool) *bool { return &b }

// ResultMeta carries optional StateKit metadata. It extends results without
// changing the Salt-compatible core fields.
type ResultMeta struct {
	Type       string `json:"type,omitempty" yaml:"type,omitempty"`
	Module     string `json:"module,omitempty" yaml:"module,omitempty"`
	Function   string `json:"function,omitempty" yaml:"function,omitempty"`
	Provider   string `json:"provider,omitempty" yaml:"provider,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty" yaml:"duration_ms,omitempty"`

	// Extra carries non-standard top-level keys some Salt states return
	// (e.g. pyenv's "default") without widening the core shape.
	Extra map[string]any `json:"extra,omitempty" yaml:"extra,omitempty"`
}

// StateResult is the core Salt state return shape:
// name, result (tri-state), changes, comment; plus optional meta.
type StateResult struct {
	Name    string         `json:"name" yaml:"name"`
	Result  *bool          `json:"result" yaml:"result"`
	Changes map[string]any `json:"changes" yaml:"changes"`
	Comment string         `json:"comment" yaml:"comment"`

	Meta *ResultMeta `json:"meta,omitempty" yaml:"meta,omitempty"`
}

// New builds a StateResult, normalizing nil changes to an empty map so the
// serialized form always carries a changes object like Salt does.
func New(name, comment string, res *bool, changes map[string]any) StateResult {
	if changes == nil {
		changes = map[string]any{}
	}
	return StateResult{Name: name, Result: res, Changes: changes, Comment: comment}
}

// Success reports a reached desired state (result: true).
func Success(name, comment string) StateResult {
	return New(name, comment, Bool(true), nil)
}

// Failure reports a failed operation (result: false).
func Failure(name, comment string) StateResult {
	return New(name, comment, Bool(false), nil)
}

// TestPending reports test-mode detection of required changes (result: null).
func TestPending(name, comment string, changes map[string]any) StateResult {
	return New(name, comment, nil, changes)
}

// Normalized returns the result with a non-nil Changes map.
func (r StateResult) Normalized() StateResult {
	if r.Changes == nil {
		r.Changes = map[string]any{}
	}
	return r
}

// Changed reports whether the result declares any changes
// (derived value: changed = len(changes) > 0).
func (r StateResult) Changed() bool { return len(r.Changes) > 0 }

// Succeeded reports whether the operation completed successfully.
// Test-mode pending results (nil Result) are not successes.
func (r StateResult) Succeeded() bool { return r.Result != nil && *r.Result }
