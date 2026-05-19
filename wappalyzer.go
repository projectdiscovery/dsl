package dsl

import (
	"bufio"
	"errors"
	"fmt"
	"net/textproto"
	"sort"
	"strings"
	"sync"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// Lazy singleton: wappalyzergo loads its embedded fingerprint database on
// construction and is safe for concurrent reads thereafter. Initializing
// on first use keeps the cost off the import path for callers that never
// touch the wappalyzer helper.
var (
	wappalyzerOnce     sync.Once
	wappalyzerInstance *wappalyzer.Wappalyze
	wappalyzerInitErr  error
)

func getWappalyzer() (*wappalyzer.Wappalyze, error) {
	wappalyzerOnce.Do(func() {
		wappalyzerInstance, wappalyzerInitErr = wappalyzer.New()
	})
	return wappalyzerInstance, wappalyzerInitErr
}

// parseHeadersForWappalyzer turns a raw HTTP header block into the
// map[string][]string shape wappalyzergo wants. It accepts the textual
// form template authors typically have on hand (the contents of nuclei's
// {{header}} variable). Header names are kept as written - wappalyzergo
// lowercases them internally.
func parseHeadersForWappalyzer(raw string) (map[string][]string, error) {
	raw = strings.TrimLeft(raw, "\r\n")
	if raw == "" {
		return map[string][]string{}, nil
	}
	if !strings.HasSuffix(raw, "\r\n\r\n") {
		if !strings.HasSuffix(raw, "\r\n") {
			raw += "\r\n"
		}
		raw += "\r\n"
	}
	tp := textproto.NewReader(bufio.NewReader(strings.NewReader(raw)))
	mh, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, fmt.Errorf("invalid header block: %w", err)
	}
	return mh, nil
}

func toHeadersAndBody(args []interface{}) (map[string][]string, []byte, error) {
	if len(args) != 2 {
		return nil, nil, ErrInvalidDslFunction
	}
	var headerRaw string
	switch v := args[0].(type) {
	case string:
		headerRaw = v
	case []byte:
		headerRaw = string(v)
	case nil:
	default:
		return nil, nil, errors.New("first argument (headers) must be a string")
	}
	var body []byte
	switch v := args[1].(type) {
	case string:
		body = []byte(v)
	case []byte:
		body = v
	case nil:
	default:
		return nil, nil, errors.New("second argument (body) must be a string or bytes")
	}
	headers, err := parseHeadersForWappalyzer(headerRaw)
	if err != nil {
		return nil, nil, err
	}
	return headers, body, nil
}

// fingerprintsAsSortedSlice returns the technology names in a stable
// alphabetical order so that callers (and the DSL result cache) see a
// deterministic value for identical inputs.
func fingerprintsAsSortedSlice(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// registerWappalyzerFunction installs the wappalyzer(headers, body)
// helper. It is called from dsl.go's init so the function is present
// before DefaultHelperFunctions is materialized.
//
// wappalyzer(headers, body) []string
//
// Runs wappalyzergo's fingerprint engine against the provided
// response headers and body and returns the detected technology
// names. headers may be the raw HTTP header block as a string (the
// most common form in nuclei templates) or a pre-built byte slice
// with the same content.
func registerWappalyzerFunction() {
	MustAddFunction(NewWithSingleSignature(
		"wappalyzer",
		"(headers, body string) []string",
		true,
		func(args ...interface{}) (interface{}, error) {
			headers, body, err := toHeadersAndBody(args)
			if err != nil {
				return nil, err
			}
			w, err := getWappalyzer()
			if err != nil {
				return nil, fmt.Errorf("wappalyzer init: %w", err)
			}
			return fingerprintsAsSortedSlice(w.Fingerprint(headers, body)), nil
		},
	))
}
