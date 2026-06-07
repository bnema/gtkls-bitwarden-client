//go:build goexperiment.runtimesecret

package secretmem

import runtime_secret "runtime/secret"

// Do runs f in Go's experimental runtime secret mode.
func Do(f func()) {
	runtime_secret.Do(f)
}
