package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChatReturnsFinishReasonAndTracesMetadataOnly(t *testing.T) {
	var trace bytes.Buffer
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-secret" {
			t.Fatalf("Authorization = %q", got)
		}
		var requestBody struct {
			MaxTokens int `json:"max_tokens"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Fatal(err)
		}
		if requestBody.MaxTokens != 9000 {
			t.Errorf("max_tokens = %d, want 9000", requestBody.MaxTokens)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{
				"message": map[string]any{
					"role":    "assistant",
					"content": "",
					"tool_calls": []any{map[string]any{
						"id": "call-1", "type": "function",
						"function": map[string]any{"name": "submit_report", "arguments": `{"report":"secret report body"}`},
					}},
				},
				"finish_reason": "tool_calls",
			}},
			"usage": map[string]any{"prompt_tokens": 7, "completion_tokens": 3},
		})
	}))
	defer server.Close()

	client := &Client{
		BaseURL:   server.URL + "/v1",
		APIKey:    "test-secret",
		Model:     "test-model",
		MaxTokens: 9000,
		Trace:     &trace,
	}
	msg, usage, err := client.Chat(context.Background(), []Message{{Role: "user", Content: "hello"}}, []Tool{})
	if err != nil {
		t.Fatal(err)
	}
	if msg.FinishReason != "tool_calls" {
		t.Fatalf("FinishReason = %q", msg.FinishReason)
	}
	if len(msg.ToolCalls) != 1 || msg.ToolCalls[0].Function.Name != "submit_report" {
		t.Fatalf("tool calls = %+v", msg.ToolCalls)
	}
	if usage.PromptTokens != 7 || usage.CompletionTokens != 3 {
		t.Fatalf("usage = %+v", usage)
	}
	traced := trace.String()
	if !strings.Contains(traced, `finish_reason="tool_calls"`) || !strings.Contains(traced, "tool_calls=1") {
		t.Fatalf("trace missing response metadata: %s", traced)
	}
	if strings.Contains(traced, "test-secret") || strings.Contains(traced, "secret report body") {
		t.Fatalf("trace leaked credential or model content: %s", traced)
	}
}
