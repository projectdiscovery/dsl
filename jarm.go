package dsl

import "golang.org/x/sync/singleflight"

var jarmFingerprints singleflight.Group

func jarmProxyFromEnvironment() string {
	// Nuclei and Aurora expose their SOCKS5 scan route using SOCKS5_PROXY.
	// Keep the previous HTTP-family variables as fallbacks for callers that
	// already place a socks5:// URL there.
	return firstNonEmptyEnv(
		"SOCKS5_PROXY", "socks5_proxy",
		"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
	)
}

// coalesceJARM suppresses only overlapping calculations. Results are not kept
// after the active callers return, so separate scans cannot observe stale data.
func coalesceJARM(key string, fingerprint func() (string, error)) (string, error) {
	value, err, _ := jarmFingerprints.Do(key, func() (interface{}, error) {
		return fingerprint()
	})
	if err != nil {
		return "", err
	}
	return value.(string), nil
}
