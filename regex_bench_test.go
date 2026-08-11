package dsl

import (
	"strconv"
	"strings"
	"testing"
)

// BenchmarkRegexFunction calls regex() the way a scan does: one pattern, a
// different subject every time, so the result cache can never hit and the
// pattern is compiled on every call.
func BenchmarkRegexFunction(b *testing.B) {
	fn := DefaultHelperFunctions["regex"]
	pattern := `(?i)<title>(.*?)</title>|X-Powered-By:\s*([\w./-]+)`
	base := strings.Repeat("filler content of the sort a real page carries ", 400)

	b.ReportAllocs()
	i := 0
	for b.Loop() {
		i++
		subject := base + strconv.Itoa(i) + "<title>Example</title>"
		if _, err := fn(pattern, subject); err != nil {
			b.Fatal(err)
		}
	}
}
