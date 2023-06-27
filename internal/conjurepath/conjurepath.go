package conjurepath

import (
	"path/filepath"
	"runtime"
)

var (
	_, base, _, _ = runtime.Caller(0)
	Root          = filepath.Join(filepath.Dir(base), "../..")
)
