package progress

import (
	"bytes"
	"strings"
	"testing"
)

func TestSpinnerEnabled(t *testing.T) {
	var b bytes.Buffer
	s := New(&b, true)
	s.Start("loading")
	s.Set("scanning")
	s.Stop()
	out := b.String()
	if !strings.Contains(out, "scanning") || !strings.Contains(out, "\033[2K") {
		t.Fatalf("unexpected spinner output: %q", out)
	}
}

func TestSpinnerDisabled(t *testing.T) {
	var b bytes.Buffer
	s := New(&b, false)
	s.Start("loading")
	s.Set("scanning")
	s.Stop()
	if b.Len() != 0 {
		t.Fatalf("disabled spinner wrote %q", b.String())
	}
}
