package dsl

import "golang.org/x/sync/singleflight"

var jarmFingerprints singleflight.Group

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
