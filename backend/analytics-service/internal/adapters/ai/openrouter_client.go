package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const completionsURL = "https://openrouter.ai/api/v1/chat/completions"

// OpenRouterClient calls the OpenRouter API using the OpenAI-compatible chat completions format.
type OpenRouterClient struct {
	apiKey string
	model  string
	http   *http.Client
}

func NewOpenRouterClient(apiKey, model string, timeout time.Duration) *OpenRouterClient {
	// Use a custom transport so TLSHandshakeTimeout matches the caller-supplied
	// deadline rather than the 10 s Go default. Without this, slow TLS
	// negotiation (e.g. Docker networking on first cold connection) causes a
	// "TLS handshake timeout" error long before the overall deadline fires.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSHandshakeTimeout = timeout

	return &OpenRouterClient{
		apiKey: apiKey,
		model:  model,
		http:   &http.Client{Timeout: timeout, Transport: transport},
	}
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	} `json:"error"`
}

func (c *OpenRouterClient) Complete(ctx context.Context, prompt string) (string, error) {
	body, err := json.Marshal(chatRequest{
		Model:    c.model,
		Messages: []chatMessage{{Role: "user", Content: prompt}},
	})
	if err != nil {
		return "", fmt.Errorf("marshal ai request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, completionsURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build ai request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("HTTP-Referer", "https://github.com/BigMoneyBigSuccess/cineMate")
	req.Header.Set("X-Title", "cineMate")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("execute ai request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read ai response body: %w", err)
	}

	var chatResp chatResponse
	if err := json.Unmarshal(raw, &chatResp); err != nil {
		return "", fmt.Errorf("decode ai response: %w", err)
	}

	if chatResp.Error != nil {
		return "", fmt.Errorf("openrouter error %d: %s", chatResp.Error.Code, chatResp.Error.Message)
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("openrouter returned no choices (status %d)", resp.StatusCode)
	}

	text := chatResp.Choices[0].Message.Content
	// Some reasoning models (e.g. deepseek-r1) wrap chain-of-thought in <think>…</think>.
	// Strip it so callers only see the final answer.
	if idx := strings.LastIndex(text, "</think>"); idx != -1 {
		text = strings.TrimSpace(text[idx+len("</think>"):])
	}

	return text, nil
}
