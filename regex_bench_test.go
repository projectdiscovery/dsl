package dsl

import (
	"strconv"
	"strings"
	"testing"
)

// benchSubjectSeq numbers benchmark subjects across the whole process, not per
// invocation. `go test -bench . -count=N` calls the benchmark function N times
// in ONE process, and `resultCache` is package-level, so a counter starting at
// zero each time would replay the same subjects and let the result cache serve
// every call from the second run onward. The benchmark then reports the cost of
// a cache hit rather than of compiling, and shows no difference between a cached
// and an uncached implementation — which is exactly what it exists to measure.
var benchSubjectSeq int

// BenchmarkRegexFunction calls regex() the way a scan does: one pattern, a
// different subject every time, so the result cache can never hit and only the
// pattern compilation is measured.
func BenchmarkRegexFunction(b *testing.B) {
	fn := DefaultHelperFunctions["regex"]
	pattern := `(?i)<title>(.*?)</title>|X-Powered-By:\s*([\w./-]+)`
	base := strings.Repeat("filler content of the sort a real page carries ", 400)

	b.ReportAllocs()
	for b.Loop() {
		benchSubjectSeq++
		subject := base + strconv.Itoa(benchSubjectSeq) + "<title>Example</title>"
		if _, err := fn(pattern, subject); err != nil {
			b.Fatal(err)
		}
	}
}
