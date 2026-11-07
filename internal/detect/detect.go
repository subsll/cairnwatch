// Package detect applies deterministic, email-only phishing indicators.
package detect

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Technique identifiers are intentionally descriptive; AttackID is populated
// when a reasonable ATT&CK mapping exists.
const (
	Cloaking           = "CLOAKING"
	Obfuscation        = "OBFUSCATION"
	Masquerading       = "MASQUERADING"
	PhishingLink       = "PHISHING_LINK"
	PhishingAttachment = "PHISHING_ATTACHMENT"
	CredentialHarvest  = "CREDENTIAL_HARVEST"
	Tracking           = "TRACKING"
	HeaderAnomaly      = "HEADER_ANOMALY"
	AuthFailure        = "AUTH_FAILURE"
	SocialEngineering  = "SOCIAL_ENGINEERING"
	URLAnomaly         = "URL_ANOMALY"
)

var techniqueATTACK = map[string]string{
	Cloaking:           "T1036",
	Obfuscation:        "T1027",
	Masquerading:       "T1036",
	PhishingLink:       "T1566.002",
	PhishingAttachment: "T1566.001",
	CredentialHarvest:  "T1598",
	HeaderAnomaly:      "T1036",
}

// Detection is one logged heuristic finding.
type Detection struct {
	ID         string `json:"id"`
	Technique  string `json:"technique"`
	AttackID   string `json:"attack_id,omitempty"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Title      string `json:"title"`
	Evidence   string `json:"evidence"`
	Location   string `json:"location"`
}

// Report is the deterministic detection log for one email.
type Report struct {
	GeneratedAt string         `json:"generated_at"`
	Techniques  []string       `json:"techniques"`
	Counts      map[string]int `json:"counts"`
	Detections  []Detection    `json:"detections"`
	Limitations []string       `json:"limitations"`
}

type content struct {
	text string
	html string
}

type envelodeDoc struct {
	Messages []struct {
		From []struct {
			Domain string `json:"domain"`
		} `json:"from"`
		ReturnPath *struct {
			Domain string `json:"domain"`
		} `json:"return_path"`
		Authentication struct {
			SPF []struct {
				Result string `json:"result"`
				Domain string `json:"domain"`
			} `json:"spf"`
			DKIM []struct {
				Result string `json:"result"`
				Domain string `json:"domain"`
			} `json:"dkim"`
			DMARC []struct {
				Result string `json:"result"`
				Domain string `json:"domain"`
			} `json:"dmarc"`
		} `json:"authentication"`
		Attachments []struct {
			Filename    string `json:"filename"`
			ContentType string `json:"content_type"`
		} `json:"attachments"`
	} `json:"messages"`
}

var (
	anchorRE      = regexp.MustCompile(`(?is)<a\b([^>]*)>(.*?)</a>`)
	hrefRE        = regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']`)
	plainURLRE    = regexp.MustCompile(`(?i)https?://[^\s<>"']+`)
	passwordRE    = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*["']?password`)
	hiddenCSSRE   = regexp.MustCompile(`(?i)(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)`)
	trackingImgRE = regexp.MustCompile(`(?i)<img[^>]+(width|height)\s*=\s*["']?1["']?`)
	tagRE         = regexp.MustCompile(`(?s)<[^>]+>`)
	domainTextRE  = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b`)
)

var shorteners = map[string]bool{
	"bit.ly": true, "tinyurl.com": true, "t.co": true, "goo.gl": true,
	"ow.ly": true, "is.gd": true, "cutt.ly": true, "rb.gy": true,
	"shorturl.at": true, "rebrand.ly": true, "s.id": true, "tiny.cc": true,
	"t.ly": true, "buff.ly": true, "lnkd.in": true,
}

var redirectParams = map[string]bool{
	"url": true, "redirect": true, "redirect_uri": true, "redirect_url": true,
	"continue": true, "target": true, "dest": true, "destination": true,
	"next": true, "goto": true, "return": true, "returnurl": true,
	"u": true, "r": true, "link": true, "out": true,
}

var dangerousExt = map[string]bool{
	".exe": true, ".scr": true, ".js": true, ".vbs": true, ".bat": true,
	".cmd": true, ".ps1": true, ".hta": true, ".jar": true, ".lnk": true,
	".iso": true, ".img": true, ".docm": true, ".xlsm": true, ".pptm": true,
	".zip": true, ".rar": true, ".7z": true, ".html": true, ".htm": true,
}

// Analyze produces a deterministic detection report. It never fetches URLs.
func Analyze(raw, envelodeJSON []byte) Report {
	c := extractContent(raw)
	text := c.text + "\n" + c.html
	var ds []Detection
	add := func(technique, severity, confidence, title, evidence, location string) {
		key := technique + "|" + title + "|" + evidence
		for _, d := range ds {
			if d.Technique+"|"+d.Title+"|"+d.Evidence == key {
				return
			}
		}
		if len(ds) >= 100 {
			return
		}
		ds = append(ds, Detection{
			Technique: technique, AttackID: techniqueATTACK[technique],
			Severity: severity, Confidence: confidence, Title: title,
			Evidence: truncate(clean(evidence), 320), Location: location,
		})
	}

	anchors := parseAnchors(c.html)
	seenText := map[string]string{}
	for _, a := range anchors {
		href := strings.TrimSpace(a.href)
		visible := strings.TrimSpace(a.text)
		if href == "" {
			continue
		}
		u, err := url.Parse(href)
		if err != nil {
			continue
		}
		host := normalizeHost(u.Hostname())
		if visible != "" {
			visibleHost := visibleDomain(visible)
			if visibleHost != "" && host != "" && visibleHost != host {
				add(Cloaking, "high", "medium", "Visible link text differs from destination",
					"visible="+visibleHost+" destination="+host, "email body")
			}
			if prev, ok := seenText[visible]; ok && prev != href {
				add(Cloaking, "high", "medium", "Same link text points to multiple destinations",
					"text="+visible+" destinations="+prev+" and "+href, "email body")
			}
			seenText[visible] = href
		}
		checkURL(u, href, add)
	}
	for _, rawURL := range plainURLRE.FindAllString(text, -1) {
		rawURL = strings.TrimRight(rawURL, ".,);]")
		if u, err := url.Parse(rawURL); err == nil {
			checkURL(u, rawURL, add)
		}
	}
	if len(anchors) > 0 && hiddenCSSRE.MatchString(c.html) {
		add(Cloaking, "medium", "low", "Hidden CSS around links",
			"hidden CSS with links present", "email HTML")
	}
	if passwordRE.MatchString(c.html) {
		add(CredentialHarvest, "high", "medium", "Password input in email HTML",
			"HTML contains a password input field", "email HTML")
	}
	if len(plainURLRE.FindAllString(text, -1)) > 0 {
		add(PhishingLink, "medium", "low", "Email contains external links",
			fmt.Sprintf("%d URL(s) found", len(plainURLRE.FindAllString(text, -1))), "email body")
	}
	if trackingImgRE.MatchString(c.html) {
		add(Tracking, "low", "low", "Tracking-pixel-like image",
			"1x1 image element found", "email HTML")
	}
	words := strings.ToLower(text)
	hits := 0
	for _, kw := range []string{"urgent", "verify your", "password", "suspend", "invoice", "payment", "mfa", "2fa", "login", "wire transfer", "gift card"} {
		if strings.Contains(words, kw) {
			hits++
		}
	}
	if hits >= 3 {
		add(SocialEngineering, "medium", "low", "Urgency or credential language",
			fmt.Sprintf("%d social-engineering keyword(s)", hits), "email body")
	}
	if strings.Contains(strings.ToLower(c.html), "base64,") || strings.Contains(strings.ToLower(c.html), "atob(") || strings.Contains(strings.ToLower(c.html), "eval(") {
		add(Obfuscation, "medium", "low", "Encoded or dynamic HTML content",
			"base64/atob/eval indicator in HTML", "email HTML")
	}

	var doc envelodeDoc
	if json.Unmarshal(envelodeJSON, &doc) == nil {
		for _, m := range doc.Messages {
			var fromDomain string
			if len(m.From) > 0 {
				fromDomain = normalizeHost(m.From[0].Domain)
			}
			var rpDomain string
			if m.ReturnPath != nil {
				rpDomain = normalizeHost(m.ReturnPath.Domain)
			}
			if fromDomain != "" && rpDomain != "" && fromDomain != rpDomain {
				add(HeaderAnomaly, "medium", "medium", "From and Return-Path domains differ",
					"from="+fromDomain+" return_path="+rpDomain, "headers")
			}
			for _, a := range []struct {
				name string
				vals []struct {
					Result string `json:"result"`
					Domain string `json:"domain"`
				}
			}{{"spf", m.Authentication.SPF}, {"dkim", m.Authentication.DKIM}, {"dmarc", m.Authentication.DMARC}} {
				for _, v := range a.vals {
					r := strings.ToLower(v.Result)
					if r == "fail" || r == "softfail" || r == "permerror" || r == "temperror" {
						add(AuthFailure, "high", "high", "Authentication failure: "+strings.ToUpper(a.name),
							"result="+v.Result+" domain="+v.Domain, "authentication headers")
					}
				}
			}
			for _, att := range m.Attachments {
				ext := strings.ToLower(filepathExt(att.Filename))
				if dangerousExt[ext] {
					add(PhishingAttachment, "high", "medium", "Risky attachment type",
						"filename="+att.Filename+" content_type="+att.ContentType, "attachments")
				}
			}
		}
	}
	sort.SliceStable(ds, func(i, j int) bool {
		rank := map[string]int{"high": 3, "medium": 2, "low": 1}
		if rank[ds[i].Severity] != rank[ds[j].Severity] {
			return rank[ds[i].Severity] > rank[ds[j].Severity]
		}
		return ds[i].Technique < ds[j].Technique
	})
	for i := range ds {
		ds[i].ID = fmt.Sprintf("D-%03d", i+1)
	}
	counts := map[string]int{}
	for _, d := range ds {
		counts[d.Technique]++
	}
	techs := make([]string, 0, len(counts))
	for t := range counts {
		techs = append(techs, t)
	}
	sort.Strings(techs)
	return Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Techniques:  techs, Counts: counts, Detections: ds,
		Limitations: []string{
			"Email-only heuristics; no URLs are fetched, no JavaScript is executed and no sandbox is used.",
			"Live cloaking that changes by user-agent, source IP or geolocation cannot be observed from the message alone.",
			"Absence of detections is not evidence that an email is benign.",
			"Indicators are investigative leads and must be verified independently.",
		},
	}
}

func checkURL(u *url.URL, rawURL string, add func(string, string, string, string, string, string)) {
	host := normalizeHost(u.Hostname())
	if host == "" {
		return
	}
	if shorteners[host] {
		add(Cloaking, "high", "medium", "URL shortener or redirector",
			"host="+host+" url="+rawURL, "email body")
	}
	if u.User != nil {
		add(URLAnomaly, "high", "high", "URL contains userinfo before host",
			"url="+rawURL, "email body")
	}
	if strings.HasPrefix(strings.ToLower(rawURL), "javascript:") || strings.HasPrefix(strings.ToLower(rawURL), "data:") {
		add(Obfuscation, "high", "high", "Script or data URI",
			"url="+rawURL, "email body")
	}
	if strings.Contains(host, "xn--") || hasNonASCII(host) {
		add(Masquerading, "high", "medium", "Punycode or non-ASCII host",
			"host="+host, "email body")
	}
	if isIP(host) {
		add(URLAnomaly, "medium", "high", "IP-literal URL",
			"host="+host, "email body")
	}
	q := u.Query()
	for k, vals := range q {
		if !redirectParams[strings.ToLower(k)] {
			continue
		}
		for _, v := range vals {
			decoded, _ := url.QueryUnescape(v)
			if strings.Contains(strings.ToLower(decoded), "http://") || strings.Contains(strings.ToLower(decoded), "https://") || domainTextRE.MatchString(decoded) {
				add(Cloaking, "high", "medium", "Redirect parameter carries a nested destination",
					"param="+k+" value="+truncate(decoded, 180), "email body")
			}
		}
	}
	if strings.Contains(strings.ToLower(rawURL), "%2f%2f") || strings.Contains(strings.ToLower(rawURL), "%3a%2f%2f") {
		add(URLAnomaly, "medium", "medium", "Encoded URL structure",
			"url="+rawURL, "email body")
	}
}

type anchor struct {
	href string
	text string
}

func parseAnchors(s string) []anchor {
	var out []anchor
	for _, m := range anchorRE.FindAllStringSubmatch(s, -1) {
		attrs, body := m[1], m[2]
		hm := hrefRE.FindStringSubmatch(attrs)
		if len(hm) != 2 {
			continue
		}
		visible := strings.TrimSpace(html.UnescapeString(tagRE.ReplaceAllString(body, " ")))
		visible = strings.Join(strings.Fields(visible), " ")
		out = append(out, anchor{href: html.UnescapeString(hm[1]), text: visible})
	}
	return out
}

func visibleDomain(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			return normalizeHost(u.Hostname())
		}
	}
	if d := domainTextRE.FindString(s); d != "" {
		return normalizeHost(d)
	}
	return ""
}

func extractContent(raw []byte) content {
	var c content
	if msg, err := mail.ReadMessage(bytes.NewReader(raw)); err == nil {
		walkMIME(msg.Header, msg.Body, &c, false)
	}
	if c.text == "" && c.html == "" {
		c.text = string(raw)
	}
	return c
}

func walkMIME(h mail.Header, body io.Reader, c *content, multipartAlreadyDecoded bool) {
	ct := h.Get("Content-Type")
	if ct == "" {
		ct = "text/plain"
	}
	media, params, _ := mime.ParseMediaType(ct)
	if strings.HasPrefix(strings.ToLower(media), "multipart/") {
		mr := multipart.NewReader(body, params["boundary"])
		for {
			p, err := mr.NextPart()
			if err != nil {
				break
			}
			walkMIME(mail.Header(p.Header), p, c, true)
		}
		return
	}
	var r io.Reader = body
	switch strings.ToLower(h.Get("Content-Transfer-Encoding")) {
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, body)
	case "quoted-printable":
		if !multipartAlreadyDecoded {
			r = quotedprintable.NewReader(body)
		}
	}
	data, _ := io.ReadAll(io.LimitReader(r, 2<<20))
	switch strings.ToLower(media) {
	case "text/html":
		c.html += string(data) + "\n"
	case "text/plain":
		c.text += string(data) + "\n"
	}
}

func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(h, ".")))
	return h
}

func hasNonASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

func isIP(s string) bool {
	// Avoid importing net for a tiny check; URLs with only digits and dots/colons.
	if strings.Contains(s, ":") || strings.Count(s, ".") == 3 {
		for _, r := range s {
			if !(r >= '0' && r <= '9' || r == '.' || r == ':') {
				return false
			}
		}
		return true
	}
	return false
}

func filepathExt(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return ""
	}
	return name[i:]
}

func clean(s string) string { return strings.Join(strings.Fields(s), " ") }
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Markdown renders the log for the case report appendix.
func Markdown(r Report) string {
	var b strings.Builder
	b.WriteString("## Automated Detection Log\n\n")
	if len(r.Detections) == 0 {
		b.WriteString("No deterministic indicators were detected. This does not prove the email is benign.\n")
	} else {
		b.WriteString("| ID | Technique | Severity | Finding | Evidence |\n")
		b.WriteString("| --- | --- | --- | --- | --- |\n")
		for _, d := range r.Detections {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", d.ID, d.Technique, d.Severity, mdCell(d.Title), mdCell(d.Evidence))
		}
	}
	b.WriteString("\n**Limitations:** ")
	for i, l := range r.Limitations {
		if i > 0 {
			b.WriteString(" ")
		}
		b.WriteString("- " + l)
	}
	b.WriteString("\n")
	return b.String()
}

func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}
