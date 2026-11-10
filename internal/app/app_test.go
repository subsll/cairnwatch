package app

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunWithMockModel(t *testing.T) {
	dir := t.TempDir()
	email := filepath.Join(dir, "phish.eml")
	raw := "From: attacker@example.com\nTo: victim@example.org\nSubject: Invoice\nContent-Type: text/html\n\n<html><body><a href=\"https://evil.example/login\">https://example.com/login</a></body></html>\n"
	if err := os.WriteFile(email, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	envelode := writeScript(t, dir, "envelode", `#!/bin/sh
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '%s' '{"messages":[{"domains":["example.com"],"subject":"Invoice"}]}' > "$out"
`)
	subsoil := writeScript(t, dir, "subsoil", `#!/bin/sh
out=""
domain=""
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    -*) shift ;;
    *) domain="$1"; shift ;;
  esac
done
mkdir -p "$out"
cat > "$out/report.json" <<JSON
{"domain":"$domain","hosts":[{"name":"www.example.com","ips":["192.0.2.10"]}],"stats":{"names_resolved":1},"evidence":{"file_sha256":"abc","chain_ok":true},"errors":[]}
JSON
printf '%s\n' "$domain  evidence.jsonl" > "$out/evidence.jsonl.sha256"
printf '%s\n' '{}' > "$out/evidence.jsonl"
`)
	stratum := writeScript(t, dir, "stratum", `#!/bin/sh
cmd="$1"; shift
case "$cmd" in
  init)
    d=""
    while [ $# -gt 0 ]; do case "$1" in --dir) d="$2"; shift 2;; *) shift;; esac; done
    mkdir -p "$d"; : > "$d/evidence.jsonl"; : > "$d/custody.jsonl"
    ;;
  add)
    w=""
    while [ $# -gt 0 ]; do case "$1" in -w) w="$2"; shift 2;; *) shift;; esac; done
    mkdir -p "$w"; printf '%s\n' '{}' >> "$w/evidence.jsonl"
    ;;
  report)
    o=""
    while [ $# -gt 0 ]; do case "$1" in -o) o="$2"; shift 2;; *) shift;; esac; done
    mkdir -p "$o"; printf '# Stratum report\n' > "$o/report.md"; printf '{}\n' > "$o/report.json"
    ;;
  verify) exit 0 ;;
esac
exit 0
`)
	reqs := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			http.Error(w, "bad auth", 401)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "subsoil_passive_dns") {
			t.Errorf("request missing tool definitions")
		}
		if !strings.Contains(string(body), `"max_tokens":9000`) {
			t.Errorf("request missing configured max_tokens: %s", body)
		}
		reqs++
		var msg map[string]any
		switch reqs {
		case 1:
			msg = toolResponse("call-1", "envelode_extract", "{}")
		case 2:
			msg = toolResponse("call-2", "subsoil_passive_dns", `{"domain":"example.com"}`)
		case 3:
			msg = toolResponse("call-3", "submit_report", `{"report":"# Investigation\n\nPhishing indicators found for example.com.\n"}`)
		default:
			http.Error(w, "too many", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(msg)
	}))
	defer server.Close()
	t.Setenv("CAIRN_TEST_KEY", "test-key")
	var out, errOut bytes.Buffer
	code := Run([]string{
		"run", "--email", email, "--case", filepath.Join(dir, "case"),
		"--case-name", "Test case", "--operator", "Tester", "--authorized",
		"--send-email-content", "--base-url", server.URL, "--model", "mock",
		"--api-key-env", "CAIRN_TEST_KEY", "--envelode-bin", envelode,
		"--subsoil-bin", subsoil, "--stratum-bin", stratum, "--verbose", "--max-tokens", "9000",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, errOut.String(), out.String())
	}
	report := filepath.Join(dir, "case", "reports", "cairnwatch-report.md")
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Phishing indicators") {
		t.Fatalf("report = %s", data)
	}
	if !strings.Contains(string(data), "CLOAKING") || !strings.Contains(string(data), "Automated Detection Log") {
		t.Fatalf("detection appendix missing: %s", data)
	}
	if _, err := os.Stat(filepath.Join(dir, "case", "evidence.jsonl")); err != nil {
		t.Fatal("case evidence missing")
	}
	if reqs != 3 {
		t.Fatalf("requests = %d", reqs)
	}
	if !strings.Contains(errOut.String(), "cairnwatch: trace: step 1/8") {
		t.Fatalf("verbose trace missing: %s", errOut.String())
	}
	if !strings.Contains(errOut.String(), "calling tool=submit_report") {
		t.Fatalf("verbose tool trace missing: %s", errOut.String())
	}
}

func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func toolResponse(id, name, args string) map[string]any {
	return map[string]any{
		"choices": []any{map[string]any{
			"message": map[string]any{
				"role": "assistant", "content": "",
				"tool_calls": []any{map[string]any{
					"id": id, "type": "function",
					"function": map[string]any{"name": name, "arguments": args},
				}},
			},
			"finish_reason": "tool_calls",
		}},
		"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
	}
}
