package file

import (
	"context"
	"fmt"

	"github.com/friz-zy/statekit/internal/renderer/gotemplate"
	"github.com/friz-zy/statekit/internal/runtime"
)

// applyTemplateOnContentsArgs mirrors Salt's full positional signature. The
// saltenv value is accepted for compatibility but is intentionally not used by
// the native, contents-only renderer.
type applyTemplateOnContentsArgs struct {
	Contents string         `statekit:"required,name=contents"`
	Template string         `statekit:"required,name=template"`
	Context  map[string]any `statekit:"name=context"`
	Defaults map[string]any `statekit:"name=defaults"`
	Saltenv  string         `statekit:"required,name=saltenv"`
}

type applyTemplateOnContentsFunc struct{}

func (applyTemplateOnContentsFunc) Name() string { return "file.apply_template_on_contents" }
func (applyTemplateOnContentsFunc) Args() any    { return applyTemplateOnContentsArgs{} }
func (applyTemplateOnContentsFunc) Execute(ctx context.Context, _ *runtime.Runtime, args any) (any, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	a := args.(*applyTemplateOnContentsArgs)
	if a.Template != "gotemplate" {
		return map[string]any{
			"result":  false,
			"comment": fmt.Sprintf("Specified template format %s is not supported", a.Template),
		}, nil
	}
	return gotemplate.Render(ctx, gotemplate.Request{
		Contents: a.Contents,
		Context:  a.Context,
		Defaults: a.Defaults,
	})
}
