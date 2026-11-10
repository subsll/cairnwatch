package investigate

import (
	"strings"
	"testing"

	"github.com/subsll/cairnwatch/internal/openai"
)

func TestFinishReasonError(t *testing.T) {
	for _, reason := range []string{"", "stop", "tool_calls"} {
		if err := finishReasonError(openai.Message{FinishReason: reason}, 8192, 100); err != nil {
			t.Fatalf("finish_reason %q returned error: %v", reason, err)
		}
	}

	err := finishReasonError(openai.Message{FinishReason: "length"}, 8192, 4000)
	if err == nil {
		t.Fatal("length finish_reason did not return an error")
	}
	for _, want := range []string{"completion token limit", "max_tokens=8192", "completion_tokens=4000", "--max-tokens"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}

	err = finishReasonError(openai.Message{FinishReason: "content_filter"}, 8192, 10)
	if err == nil || !strings.Contains(err.Error(), "content_filter") {
		t.Fatalf("content_filter error = %v", err)
	}
}
