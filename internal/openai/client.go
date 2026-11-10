// Package openai implements the small subset of the OpenAI chat-completions
// API needed by Cairnwatch.
package openai

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

// Client is an OpenAI-compatible chat-completions client.
type Client struct {
	BaseURL string
	APIKey  string
	Model   string
	HTTP    *http.Client
	// Trace, when non-nil, receives model-step metadata. It must never receive
	// the API key, message bodies, tool arguments, or tool results.
	Trace io.Writer
}

// Message is one chat message, including tool calls and tool results.
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	Name       string     `json:"name,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`

	// FinishReason is populated by Client.Chat from the response choice and is
	// not part of the chat protocol.
	FinishReason string `json:"-"`
}

// ToolCall is a function call requested by the model.
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

// FunctionCall contains the function name and JSON-encoded arguments.
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// Tool describes a callable function.
type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

// ToolFunction is the JSON schema for a tool.
type ToolFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// Usage reports token usage when the provider supplies it.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type chatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Tools       []Tool    `json:"tools,omitempty"`
	ToolChoice  string    `json:"tool_choice,omitempty"`
	Temperature float64   `json:"temperature,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message      Message `json:"message"`
		FinishReason string  `json:"finish_reason"`
	} `json:"choices"`
	Usage Usage `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

func (c *Client) tracef(format string, args ...any) {
	if c.Trace == nil {
		return
	}
	fmt.Fprintf(c.Trace, "cairnwatch: model: "+format+"\n", args...)
}

// Chat sends one non-streaming chat-completions request.
func (c *Client) Chat(ctx context.Context, messages []Message, tools []Tool) (Message, Usage, error) {
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 120 * time.Second}
	}
	body, err := json.Marshal(chatRequest{
		Model: c.Model, Messages: messages, Tools: tools, ToolChoice: "auto",
		Temperature: 0.2, MaxTokens: 4000,
	})
	if err != nil {
		return Message{}, Usage{}, err
	}
	endpoint := strings.TrimRight(c.BaseURL, "/")
	if !strings.HasSuffix(endpoint, "/chat/completions") {
		endpoint += "/chat/completions"
	}
	c.tracef("POST %s model=%q messages=%d tools=%d", endpoint, c.Model, len(messages), len(tools))
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return Message{}, Usage{}, ctx.Err()
			case <-time.After(time.Duration(attempt*2) * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return Message{}, Usage{}, err
		}
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "cairnwatch/0.3.1")
		c.tracef("request attempt %d/3", attempt+1)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			c.tracef("request attempt %d failed: %v", attempt+1, err)
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			c.tracef("read attempt %d failed: %v", attempt+1, readErr)
			continue
		}
		var parsed chatResponse
		if err := json.Unmarshal(data, &parsed); err != nil {
			lastErr = fmt.Errorf("decode API response (HTTP %d): %w", resp.StatusCode, err)
			c.tracef("decode attempt %d failed: HTTP %d: %v", attempt+1, resp.StatusCode, err)
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			msg := strings.TrimSpace(string(data))
			if parsed.Error != nil && parsed.Error.Message != "" {
				msg = parsed.Error.Message
			}
			lastErr = fmt.Errorf("API HTTP %d: %s", resp.StatusCode, truncate(msg, 500))
			c.tracef("response attempt %d: HTTP %d error=%q", attempt+1, resp.StatusCode, truncate(msg, 300))
			if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
				continue
			}
			return Message{}, Usage{}, lastErr
		}
		if len(parsed.Choices) == 0 {
			return Message{}, Usage{}, fmt.Errorf("API returned no choices")
		}
		choice := parsed.Choices[0]
		choice.Message.FinishReason = choice.FinishReason
		c.tracef("response attempt %d: HTTP %d finish_reason=%q content_bytes=%d tool_calls=%d", attempt+1, resp.StatusCode, choice.FinishReason, len(choice.Message.Content), len(choice.Message.ToolCalls))
		return choice.Message, parsed.Usage, nil
	}
	return Message{}, Usage{}, lastErr
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
