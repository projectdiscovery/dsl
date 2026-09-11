// Package llm backs the llm_prompt DSL helper. It delegates to the shared
// provider layer (github.com/projectdiscovery/utils/llm) so the helper gains
// provider choice, local-model support, caching, and a timeout without
// embedding its own client.
package llm

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	utilsllm "github.com/projectdiscovery/utils/llm"
)

// Configuration comes from the environment, since a DSL helper has no other
// place to carry it. With no LLM_BASE_URL or LLM_PROVIDER, the helper keeps the
// historical OpenAI + gpt-4o-mini default so existing OPENAI_API_KEY setups
// keep working.
const (
	envBaseURL  = "LLM_BASE_URL"
	envProvider = "LLM_PROVIDER"
	envModel    = "LLM_MODEL"

	// envAPIKey is the shared layer's key var; envLegacyAPIKey keeps the old
	// llm_prompt behaviour working for callers that still set OPENAI_API_KEY.
	envAPIKey       = "LLM_API_KEY"
	envLegacyAPIKey = "OPENAI_API_KEY"

	defaultProvider       = "openai"
	defaultModel          = "gpt-4o-mini"
	defaultTimeout        = 30 * time.Second
	defaultMaxConcurrency = 4
	defaultMaxCalls       = 1024
)

// clients are memoized per (provider, base-url, model) so caching persists
// across calls within a process rather than resetting on every llm_prompt
// invocation.
var (
	clientsMu sync.Mutex
	clients   = map[string]*utilsllm.Client{}
)

func client(model string) (*utilsllm.Client, error) {
	cfg := newConfig(model)
	key := cfg.Provider + "\x00" + cfg.BaseURL + "\x00" + model

	clientsMu.Lock()
	defer clientsMu.Unlock()

	if c, ok := clients[key]; ok {
		return c, nil
	}

	c, err := utilsllm.New(cfg)
	if err != nil {
		return nil, err
	}

	clients[key] = c

	return c, nil
}

func newConfig(model string) utilsllm.Config {
	cfg := utilsllm.Config{
		Model:          model,
		APIKey:         apiKey(),
		Cache:          true,
		Timeout:        defaultTimeout,
		MaxConcurrency: defaultMaxConcurrency,
		MaxCalls:       defaultMaxCalls,
	}

	if base := strings.TrimSpace(os.Getenv(envBaseURL)); base != "" {
		cfg.BaseURL = base
	}
	if provider := strings.TrimSpace(os.Getenv(envProvider)); provider != "" {
		cfg.Provider = provider
	} else if cfg.BaseURL == "" {
		cfg.Provider = defaultProvider
	}

	return cfg
}

func resetClients() {
	clientsMu.Lock()
	defer clientsMu.Unlock()
	clients = map[string]*utilsllm.Client{}
}

// apiKey resolves the provider key, preferring the shared LLM_API_KEY and
// falling back to OPENAI_API_KEY so existing llm_prompt setups keep working.
func apiKey() string {
	if key := os.Getenv(envAPIKey); key != "" {
		return key
	}

	return os.Getenv(envLegacyAPIKey)
}

func resolveModel(model string) string {
	if model != "" {
		return model
	}
	if model = os.Getenv(envModel); model != "" {
		return model
	}
	return defaultModel
}

// Query runs a prompt and returns the completion. The model falls back to
// LLM_MODEL, then to a default, so callers that pass no model still work.
func Query(prompt, model string) (string, error) {
	return QueryJSON(prompt, model, false)
}

// QueryJSON is Query with an optional request for a JSON response, used when a
// DSL payload needs parseable output rather than prose.
func QueryJSON(prompt, model string, asJSON bool) (string, error) {
	model = resolveModel(model)

	c, err := client(model)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	return c.Complete(ctx, utilsllm.Request{
		Prompt: prompt,
		Format: utilsllm.Format{JSON: asJSON},
	})
}
