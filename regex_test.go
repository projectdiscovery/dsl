package dsl

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// withRegexCacheSize gives the test a fresh compiled-regex cache of size and
// restores the default afterwards.
func withRegexCacheSize(t *testing.T, size int) {
	t.Helper()
	SetRegexCacheSize(size)
	t.Cleanup(func() { SetRegexCacheSize(DefaultCacheSize) })
}

func regexCacheLen(t *testing.T) int {
	t.Helper()
	cache := compiledRegexCache.Load()
	require.NotNil(t, cache)
	return (*cache).Len(false)
}

func TestCompileRegexCache(t *testing.T) {
	withRegexCacheSize(t, DefaultCacheSize)

	_, err := compileRegex("(")
	require.Error(t, err)
	_, err = compileRegex(strings.Repeat("a", maxCachedRegexLen+1))
	require.NoError(t, err)
	require.Zero(t, regexCacheLen(t), "invalid and oversized patterns must not be cached")

	first, err := compileRegex("a+b")
	require.NoError(t, err)
	second, err := compileRegex("a+b")
	require.NoError(t, err)
	require.Same(t, first, second)
}

func TestSetRegexCacheSize(t *testing.T) {
	withRegexCacheSize(t, 2)

	for i := range 3 {
		_, err := compileRegex("p" + strconv.Itoa(i))
		require.NoError(t, err)
	}
	require.Equal(t, 2, regexCacheLen(t), "cache must hold no more than the configured size")

	SetRegexCacheSize(0)
	require.Nil(t, compiledRegexCache.Load())
	first, err := compileRegex("a+b")
	require.NoError(t, err)
	second, err := compileRegex("a+b")
	require.NoError(t, err)
	require.NotSame(t, first, second, "a disabled cache must compile on every call")
}
