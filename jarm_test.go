package dsl

import (
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCoalesceJARMOnlyRunsOverlappingFingerprintOnce(t *testing.T) {
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan struct {
		value string
		err   error
	}, 1)
	var calls atomic.Int32

	go func() {
		value, err := coalesceJARM("proxy\x00example.test:443", func() (string, error) {
			calls.Add(1)
			close(firstStarted)
			<-releaseFirst
			return "fingerprint", nil
		})
		firstDone <- struct {
			value string
			err   error
		}{value: value, err: err}
	}()

	<-firstStarted
	time.AfterFunc(10*time.Millisecond, func() { close(releaseFirst) })
	value, err := coalesceJARM("proxy\x00example.test:443", func() (string, error) {
		calls.Add(1)
		return "duplicate", nil
	})

	require.NoError(t, err)
	require.Equal(t, "fingerprint", value)
	first := <-firstDone
	require.NoError(t, first.err)
	require.Equal(t, "fingerprint", first.value)
	require.EqualValues(t, 1, calls.Load())
}

func TestCoalesceJARMDoesNotCacheCompletedFingerprint(t *testing.T) {
	var calls atomic.Int32
	for range 2 {
		value, err := coalesceJARM("direct\x00example.test:443", func() (string, error) {
			calls.Add(1)
			return "fingerprint", nil
		})
		require.NoError(t, err)
		require.Equal(t, "fingerprint", value)
	}
	require.EqualValues(t, 2, calls.Load())
}

func TestJARMProxyPrefersConfiguredSOCKS5Route(t *testing.T) {
	t.Setenv("SOCKS5_PROXY", "socks5://scan-route.example:1080")
	t.Setenv("HTTP_PROXY", "socks5://legacy-http.example:1080")
	t.Setenv("HTTPS_PROXY", "socks5://legacy-https.example:1080")
	if runtime.GOOS != "windows" {
		// Windows environment variable names are case-insensitive, so setting
		// these aliases would overwrite the uppercase variables above.
		t.Setenv("socks5_proxy", "socks5://lowercase.example:1080")
		t.Setenv("http_proxy", "socks5://legacy-http-lower.example:1080")
		t.Setenv("https_proxy", "socks5://legacy-https-lower.example:1080")
	}

	require.Equal(t, "socks5://scan-route.example:1080", jarmProxyFromEnvironment())
}

func TestJARMProxyRetainsLegacyFallback(t *testing.T) {
	t.Setenv("SOCKS5_PROXY", "")
	t.Setenv("HTTP_PROXY", "socks5://legacy.example:1080")
	t.Setenv("HTTPS_PROXY", "")
	if runtime.GOOS != "windows" {
		t.Setenv("socks5_proxy", "")
		t.Setenv("http_proxy", "")
		t.Setenv("https_proxy", "")
	}

	require.Equal(t, "socks5://legacy.example:1080", jarmProxyFromEnvironment())
}
