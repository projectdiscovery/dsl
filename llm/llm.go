// Package llm backs the llm_prompt DSL helper. It delegates to the shared
// provider layer (github.com/projectdiscovery/utils/llm) so the helper gains
// provider choice, local-model support, caching, and a timeout without
// embedding its own client.
package llm

import (
	"context"
	"os"
	"sync"
	"time"

	utilsllm "github.com/projectdiscovery/utils/llm"
)

// Configuration comes from the environment, since a DSL helper has no other
// place to carry it. Defaults target OpenAI with gpt-4o-mini so existing use is
// unchanged; setting LLM_BASE_URL points the helper at a local or self-hosted
// model.
const (
	envBaseURL = "LLM_BASE_URL"
	envModel   = "LLM_MODEL"

	defaultModel   = "gpt-4o-mini"
	defaultTimeout = 30 * time.Second
)

// clients are memoized per (base-url, model) so caching persists across calls
// within a process rather than resetting on every llm_prompt invocation.
var (
	clientsMu sync.Mutex
	clients   = map[string]*utilsllm.Client{}
)

func client(model string) (*utilsllm.Client, error) {
	baseURL := os.Getenv(envBaseURL)
	key := baseURL + "\x00" + model

	clientsMu.Lock()
	defer clientsMu.Unlock()

	if c, ok := clients[key]; ok {
		return c, nil
	}

	c, err := utilsllm.New(utilsllm.Config{
		BaseURL: baseURL,
		Model:   model,
		Cache:   true,
		Timeout: defaultTimeout,
	})
	if err != nil {
		return nil, err
	}

	clients[key] = c

	return c, nil
}

// Query runs a prompt and returns the completion. The model falls back to
// LLM_MODEL, then to a default, so callers that pass no model still work.
func Query(prompt, model string) (string, error) {
	return QueryJSON(prompt, model, false)
}

// QueryJSON is Query with an optional request for a JSON response, used when a
// DSL payload needs parseable output rather than prose.
func QueryJSON(prompt, model string, asJSON bool) (string, error) {
	if model == "" {
		if model = os.Getenv(envModel); model == "" {
			model = defaultModel
		}
	}

	c, err := client(model)
	if err != nil {
		return "", err
	}

	return c.Complete(context.Background(), utilsllm.Request{
		Prompt: prompt,
		Format: utilsllm.Format{JSON: asJSON},
	})
}
