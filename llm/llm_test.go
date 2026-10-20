package llm

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func okBody(content string) string {
	return fmt.Sprintf(`{"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":%q}}]}`, content)
}

func stubServer(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server.URL + "/v1"
}

func withFreshClients(t *testing.T) {
	t.Helper()
	resetClients()
	t.Cleanup(resetClients)
}

func TestDefaultProviderRequiresKey(t *testing.T) {
	withFreshClients(t)
	t.Setenv(envBaseURL, "")
	t.Setenv(envProvider, "")
	t.Setenv(envAPIKey, "")
	t.Setenv(envLegacyAPIKey, "")

	_, err := Query("hi", "")
	require.ErrorContains(t, err, "llm api key required")
}

func TestLocalProviderDoesNotRequireKey(t *testing.T) {
	withFreshClients(t)
	t.Setenv(envBaseURL, "")
	t.Setenv(envProvider, "ollama")
	t.Setenv(envAPIKey, "")
	t.Setenv(envLegacyAPIKey, "")

	_, err := client(defaultModel)
	require.NoError(t, err)
}

func TestLegacyAPIKeyReachesAuthorizationHeader(t *testing.T) {
	withFreshClients(t)
	t.Setenv(envAPIKey, "")
	t.Setenv(envLegacyAPIKey, "legacy-key")
	t.Setenv(envProvider, "")

	var gotAuth, gotModel string
	var wantJSON bool
	t.Setenv(envBaseURL, stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		var payload struct {
			Model          string `json:"model"`
			ResponseFormat *struct {
				Type string `json:"type"`
			} `json:"response_format"`
		}
		_ = json.Unmarshal(raw, &payload)
		gotModel = payload.Model
		wantJSON = payload.ResponseFormat != nil && payload.ResponseFormat.Type == "json_object"
		_, _ = w.Write([]byte(okBody("ok")))
	}))

	got, err := QueryJSON("hi", "", true)
	require.NoError(t, err)
	require.Equal(t, "ok", got)
	require.Equal(t, "Bearer legacy-key", gotAuth)
	require.Equal(t, defaultModel, gotModel)
	require.True(t, wantJSON)
}

func TestLLMAPIKeyWinsOverLegacy(t *testing.T) {
	withFreshClients(t)
	t.Setenv(envAPIKey, "shared-key")
	t.Setenv(envLegacyAPIKey, "legacy-key")
	t.Setenv(envProvider, "")

	var gotAuth string
	t.Setenv(envBaseURL, stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(okBody("ok")))
	}))

	_, err := Query("hi", "custom-model")
	require.NoError(t, err)
	require.Equal(t, "Bearer shared-key", gotAuth)
}

func TestEnvModelOverride(t *testing.T) {
	withFreshClients(t)
	t.Setenv(envAPIKey, "k")
	t.Setenv(envModel, "env-model")
	t.Setenv(envProvider, "")

	var gotModel string
	t.Setenv(envBaseURL, stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var payload struct {
			Model string `json:"model"`
		}
		_ = json.Unmarshal(raw, &payload)
		gotModel = payload.Model
		_, _ = w.Write([]byte(okBody("ok")))
	}))

	_, err := Query("hi", "")
	require.NoError(t, err)
	require.Equal(t, "env-model", gotModel)
}

func TestNewConfigDefaults(t *testing.T) {
	t.Setenv(envBaseURL, "")
	t.Setenv(envProvider, "")
	cfg := newConfig("m")
	require.Equal(t, defaultProvider, cfg.Provider)
	require.Equal(t, "m", cfg.Model)
	require.Equal(t, defaultMaxConcurrency, cfg.MaxConcurrency)
	require.Equal(t, defaultMaxCalls, cfg.MaxCalls)
	require.True(t, cfg.Cache)
}

func TestNewConfigRespectsProviderAndBaseURL(t *testing.T) {
	t.Setenv(envProvider, "ollama")
	t.Setenv(envBaseURL, "http://host:9/v1")
	cfg := newConfig("m")
	require.Equal(t, "ollama", cfg.Provider)
	require.Equal(t, "http://host:9/v1", cfg.BaseURL)
}
