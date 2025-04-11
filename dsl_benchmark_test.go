package dsl

import (
	"testing"
	"time"

	"github.com/Knetic/govaluate"
)

func BenchmarkDSLCaching(b *testing.B) {
	// simple function that has some computational cost
	computeFunc := func(args ...interface{}) (interface{}, error) {
		time.Sleep(time.Microsecond)
		return "computed value", nil
	}

	funcs := make(map[string]dslFunction)
	funcs["cached_func"] = dslFunction{
		IsCacheable:        true,
		Name:               "cached_func",
		NumberOfArgs:       1,
		Signatures:         nil,
		ExpressionFunction: computeFunc,
	}
	funcs["uncached_func"] = dslFunction{
		IsCacheable:        false,
		Name:               "uncached_func",
		NumberOfArgs:       1,
		Signatures:         nil,
		ExpressionFunction: computeFunc,
	}

	exprs := make(map[string]govaluate.ExpressionFunction)
	for name, fn := range funcs {
		exprs[name] = fn.Exec
	}

	resultCache.Purge()

	evaluateForBenchmark := func(b *testing.B, fn string, args ...any) any {
		res, err := exprs[fn](args...)
		if err != nil {
			b.Fatalf("Error evaluating expression: %v", err)
		}
		return res
	}

	b.Run("Cached-single", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			evaluateForBenchmark(b, "cached_func", 1)
		}
	})

	b.Run("Uncached-single", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			evaluateForBenchmark(b, "uncached_func", 1)
		}
	})

	// test cache key generation

	b.Run("Cached-diff", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			evaluateForBenchmark(b, "cached_func", i%100)
		}
	})

	b.Run("Uncached-diff", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			evaluateForBenchmark(b, "uncached_func", i%100)
		}
	})

	// test cache hit

	b.Run("Cached-repeat", func(b *testing.B) {
		// Pre-warm
		for i := 0; i < 10; i++ {
			evaluateForBenchmark(b, "cached_func", i)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			evaluateForBenchmark(b, "cached_func", i%10)
		}
	})

	b.Run("Uncached-repeat", func(b *testing.B) {
		// Pre-warm
		for i := 0; i < 10; i++ {
			evaluateForBenchmark(b, "uncached_func", i)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			evaluateForBenchmark(b, "uncached_func", i%10)
		}
	})
}
