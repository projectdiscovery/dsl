package dsl

import (
	"fmt"
	"strings"
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

func BenchmarkDSLFunctionHash(b *testing.B) {
	name := "test_func"
	args := []any{
		"arg1",
		int(12345),
		int8(-12),
		int16(1234),
		int32(-123456),
		int64(1234567890),
		uint(54321),
		uint8(250),
		uint16(54321),
		uint32(1234567890),
		uint64(9876543210),
		float32(123.456),
		float64(123.4567890123),
		true,
		"a-very-long-argument-to-make-hashing-non-trivial",
		[]byte("some bytes"),
	}

	// NOTE(dwisiswant0): Copied from https://github.com/projectdiscovery/dsl/blob/3a6a901037affe56a31a3345573d8384d0ff5128/func.go#L70-L83
	oldDSLFunctionHasher := func(name string, args ...interface{}) string {
		var sb strings.Builder
		_, _ = sb.WriteString(name)
		_, _ = sb.WriteString("-")

		for i, arg := range args {
			_, _ = sb.WriteString(fmt.Sprintf("%v", arg))
			if i < len(args)-1 {
				_, _ = sb.WriteString(",")
			}
		}

		return sb.String()
	}

	b.Run("builder", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			oldDSLFunctionHasher(name, args...)
		}
	})

	b.Run("fnv", func(b *testing.B) {
		d := dslFunction{Name: name}

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = d.hash(args...)
		}
	})
}
