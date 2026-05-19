package dsl

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// callWappalyzer invokes the registered "wappalyzer" DSL helper and
// returns the sorted slice of detected technology names.
func callWappalyzer(t *testing.T, headers, body string) []string {
	t.Helper()
	fn, ok := DefaultHelperFunctions["wappalyzer"]
	require.True(t, ok, "wappalyzer DSL function must be registered")
	got, err := fn(headers, body)
	require.NoError(t, err)
	techs, ok := got.([]string)
	require.True(t, ok, "wappalyzer must return []string, got %T", got)
	return techs
}

// TestWappalyzerRegistered pins the function's public surface so a
// rename/regression is caught before consumers do.
func TestWappalyzerRegistered(t *testing.T) {
	require.Contains(t, FunctionNames, "wappalyzer")
	_, ok := DefaultHelperFunctions["wappalyzer"]
	require.True(t, ok)
}

// TestWappalyzerDetectsNginx covers the most basic header-only match.
// The Server response header is the canonical wappalyzergo trigger for
// nginx detection.
func TestWappalyzerDetectsNginx(t *testing.T) {
	techs := callWappalyzer(t, "Server: nginx/1.25.3\r\n", "")
	require.Contains(t, techs, "Nginx:1.25.3")
}

// TestWappalyzerDetectsFromBody confirms the body path also feeds the
// fingerprint engine. The generator meta tag is a stable WordPress
// indicator.
func TestWappalyzerDetectsFromBody(t *testing.T) {
	body := `<html><head><meta name="generator" content="WordPress 6.5.3"/></head><body></body></html>`
	techs := callWappalyzer(t, "", body)
	require.NotEmpty(t, techs)
	requireHasPrefix(t, techs, "WordPress")
}

// TestWappalyzerEmptyInputs documents that no headers and no body
// produce an empty slice instead of an error, so templates can call
// the helper unconditionally without guarding against missing data.
func TestWappalyzerEmptyInputs(t *testing.T) {
	techs := callWappalyzer(t, "", "")
	require.Equal(t, []string{}, techs)
}

// TestWappalyzerHeadersAcceptBytes confirms the helper accepts both
// string and []byte for both arguments, matching how nuclei substitutes
// template variables (sometimes string, sometimes raw bytes for body).
func TestWappalyzerHeadersAcceptBytes(t *testing.T) {
	fn := DefaultHelperFunctions["wappalyzer"]
	got, err := fn([]byte("Server: nginx\r\n"), []byte(""))
	require.NoError(t, err)
	require.Contains(t, got.([]string), "Nginx")
}

// TestWappalyzerNilArgs treats nil arguments as empty input, mirroring
// the behavior of unset nuclei variables.
func TestWappalyzerNilArgs(t *testing.T) {
	fn := DefaultHelperFunctions["wappalyzer"]
	got, err := fn(nil, nil)
	require.NoError(t, err)
	require.Equal(t, []string{}, got)
}

// TestWappalyzerRejectsWrongTypes guarantees we don't silently
// fingerprint bogus inputs (e.g. an integer where the body should be).
func TestWappalyzerRejectsWrongTypes(t *testing.T) {
	fn := DefaultHelperFunctions["wappalyzer"]
	_, err := fn(42, "body")
	require.Error(t, err)
	_, err = fn("Server: nginx\r\n", 42)
	require.Error(t, err)
}

// TestWappalyzerArgCount checks the function rejects the wrong arity.
func TestWappalyzerArgCount(t *testing.T) {
	fn := DefaultHelperFunctions["wappalyzer"]
	_, err := fn("Server: nginx\r\n")
	require.Error(t, err)
	_, err = fn("Server: nginx\r\n", "", "extra")
	require.Error(t, err)
}

// TestWappalyzerReturnsSorted pins the deterministic ordering used by
// the DSL result cache and downstream comparisons. Multiple fingerprint
// hits must come back sorted in ascending alphabetical order.
func TestWappalyzerReturnsSorted(t *testing.T) {
	// Two independent fingerprints to force a non-trivial set.
	headers := "Server: nginx/1.25.3\r\nX-Powered-By: PHP/8.2.0\r\n"
	techs := callWappalyzer(t, headers, "")
	require.Greater(t, len(techs), 1, "need at least two hits to verify ordering")
	for i := 1; i < len(techs); i++ {
		require.LessOrEqual(t, techs[i-1], techs[i], "expected sorted output, got %v", techs)
	}
}

// TestWappalyzerHeaderParsingTolerant covers header blocks that have or
// lack the standard "\r\n\r\n" terminator, so template authors don't
// have to think about framing.
func TestWappalyzerHeaderParsingTolerant(t *testing.T) {
	for _, raw := range []string{
		"Server: nginx",
		"Server: nginx\r\n",
		"Server: nginx\r\n\r\n",
		"\r\nServer: nginx\r\n",
	} {
		t.Run(raw, func(t *testing.T) {
			techs := callWappalyzer(t, raw, "")
			require.Contains(t, techs, "Nginx")
		})
	}
}

// TestWappalyzerInvalidHeaderBlockSurfacesError makes sure obviously
// malformed input is reported instead of silently dropped, so template
// authors get a useful signal when the header variable is corrupt.
func TestWappalyzerInvalidHeaderBlockSurfacesError(t *testing.T) {
	fn := DefaultHelperFunctions["wappalyzer"]
	_, err := fn("this line has no colon\r\n", "")
	require.Error(t, err)
}

// TestWappalyzerCached confirms the helper participates in the DSL
// result cache (IsCacheable: true). We can't easily inspect the cache
// from outside the package, but we can pin that repeated invocations
// with identical inputs return equal results.
func TestWappalyzerCached(t *testing.T) {
	a := callWappalyzer(t, "Server: nginx/1.25.3\r\n", "")
	b := callWappalyzer(t, "Server: nginx/1.25.3\r\n", "")
	require.Equal(t, a, b)
}

func requireHasPrefix(t *testing.T, techs []string, prefix string) {
	t.Helper()
	for _, tech := range techs {
		if len(tech) >= len(prefix) && tech[:len(prefix)] == prefix {
			return
		}
	}
	t.Fatalf("expected a tech with prefix %q in %v", prefix, techs)
}
