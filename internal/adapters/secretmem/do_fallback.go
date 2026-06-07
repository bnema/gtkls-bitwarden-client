//go:build !goexperiment.runtimesecret

package secretmem

// Do runs f directly when runtime/secret is not enabled at build time.
func Do(f func()) {
	f()
}
