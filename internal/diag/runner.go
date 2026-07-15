package diag

import "context"

type Runner interface {
	Run(ctx context.Context, target Target, cmd RenderedCommand) (RawResult, error)
}
