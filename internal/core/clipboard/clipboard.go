package clipboard

import "time"

type Policy struct {
	ClearAfter     time.Duration
	CloseAfterCopy bool
}
