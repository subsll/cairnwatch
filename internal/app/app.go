// Package app implements the Cairnwatch command line.
package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/subsll/cairnwatch/internal/investigate"
	"github.com/subsll/cairnwatch/internal/openai"
	"github.com/subsll/cairnwatch/internal/progress"
)

var Version = "0.3.0"

// Run executes the CLI.
func Run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		usage(errOut)
		return 2
	}
	switch args[0] {
	case "run", "investigate":
		return run(args[1:], out, errOut)
	case "version", "--version", "-version":
		fmt.Fprintf(out, "cairnwatch %s (%s %s/%s)\n", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return 0
	case "help", "--help", "-h":
		usage(out)
		return 0
	default:
		fmt.Fprintf(errOut, "cairnwatch: unknown command %q\n", args[0])
		usage(errOut)
		return 2
	}
}

func run(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("cairnwatch run", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var (
		email, caseDir, caseName, operator, org      string
		authorized, sendContent, keepWork, noSpinner bool
		workDir, sources                             string
		envelode, subsoil, stratum                   string
		baseURL, model, apiKeyEnv                    string
		timeout                                      time.Duration
		maxSteps, maxEmailBytes                      int
		scopes                                       stringList
	)
	fs.StringVar(&email, "email", "", "raw .eml/email file (required)")
	fs.StringVar(&caseDir, "case", "", "new Stratum case directory (required)")
	fs.StringVar(&caseName, "case-name", "", "case title")
	fs.StringVar(&operator, "operator", "", "operator name (required)")
	fs.StringVar(&org, "org", "", "operator organisation")
	fs.BoolVar(&authorized, "authorized", false, "required: confirm authorised defensive analysis")
	fs.BoolVar(&sendContent, "send-email-content", false, "send raw email body to the configured model API")
	fs.Var(&scopes, "scope", "additional allowed domain (repeatable)")
	fs.StringVar(&workDir, "workdir", "", "analysis working directory")
	fs.BoolVar(&keepWork, "keep-work", false, "keep the working directory")
	fs.BoolVar(&noSpinner, "no-spinner", false, "disable the terminal progress spinner")
	fs.StringVar(&envelode, "envelode-bin", "envelode", "Envelode binary")
	fs.StringVar(&subsoil, "subsoil-bin", "subsoil", "Subsoil binary")
	fs.StringVar(&stratum, "stratum-bin", "stratum", "Stratum binary")
	fs.StringVar(&sources, "subsoil-sources", "crt.sh,certspotter", "passive sources for Subsoil")
	fs.DurationVar(&timeout, "timeout", 10*time.Minute, "overall run timeout")
	fs.IntVar(&maxSteps, "max-steps", 8, "maximum model/tool steps")
	fs.IntVar(&maxEmailBytes, "max-email-bytes", 200000, "maximum email bytes sent to the model")
	fs.StringVar(&baseURL, "base-url", envOr("OPENAI_BASE_URL", "https://api.openai.com/v1"), "OpenAI-compatible base URL")
	fs.StringVar(&model, "model", envOr("OPENAI_MODEL", "gpt-4o-mini"), "model name")
	fs.StringVar(&apiKeyEnv, "api-key-env", "OPENAI_API_KEY", "environment variable holding the API key")
	fs.Usage = func() {
		fmt.Fprintln(errOut, "usage: cairnwatch run --email <file> --case <dir> --operator <name> --authorized [flags]")
		fmt.Fprintln(errOut, "")
		fmt.Fprintln(errOut, "Runs Envelode + passive Subsoil under an OpenAI-compatible analyst model")
		fmt.Fprintln(errOut, "and preserves the source, outputs and report in a Stratum case.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(out)
			fs.Usage()
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(errOut, "cairnwatch: unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	if !authorized {
		fmt.Fprintln(errOut, "cairnwatch: refusing to run without --authorized")
		fmt.Fprintln(errOut, "Use only on email and infrastructure you own or are explicitly authorised to investigate.")
		return 2
	}
	if email == "" || caseDir == "" || operator == "" {
		fmt.Fprintln(errOut, "cairnwatch: --email, --case and --operator are required")
		fs.Usage()
		return 2
	}
	if sendContent {
		fmt.Fprintf(errOut, "warning: raw email content will be sent to %s\n", baseURL)
	} else {
		fmt.Fprintln(errOut, "note: raw email content will NOT be sent to the model; use --send-email-content to enable content analysis")
	}
	key := os.Getenv(apiKeyEnv)
	if strings.TrimSpace(key) == "" {
		fmt.Fprintf(errOut, "cairnwatch: API key environment variable %s is empty\n", apiKeyEnv)
		return 2
	}
	if err := checkBinary(envelode); err != nil {
		fmt.Fprintf(errOut, "cairnwatch: Envelode binary: %v\n", err)
		return 2
	}
	if err := checkBinary(subsoil); err != nil {
		fmt.Fprintf(errOut, "cairnwatch: Subsoil binary: %v\n", err)
		return 2
	}
	if err := checkBinary(stratum); err != nil {
		fmt.Fprintf(errOut, "cairnwatch: Stratum binary: %v\n", err)
		return 2
	}

	cfg := investigate.Config{
		Email: email, CaseDir: caseDir, CaseName: caseName, Operator: operator, Org: org,
		Authorized: authorized, SendEmailContent: sendContent, Scope: scopes,
		Envelode: envelode, Subsoil: subsoil, Stratum: stratum, Sources: sources,
		Timeout: timeout, MaxSteps: maxSteps, MaxEmailBytes: maxEmailBytes,
		KeepWork: keepWork, WorkDir: workDir,
		Client: &openai.Client{BaseURL: baseURL, APIKey: key, Model: model},
	}
	sp := progress.New(errOut, !noSpinner && progress.IsTerminal(os.Stderr) && os.Getenv("TERM") != "dumb")
	cfg.Progress = sp.Set
	sp.Start("starting investigation")
	defer sp.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	res, err := investigate.Run(ctx, cfg)
	sp.Stop()
	if err != nil {
		fmt.Fprintf(errOut, "cairnwatch: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "case:           %s\n", caseDir)
	fmt.Fprintf(out, "report:         %s\n", res.ReportPath)
	fmt.Fprintf(out, "stratum report: %s\n", res.StratumReportPath)
	fmt.Fprintf(out, "evidence:       %s\n", res.EvidencePath)
	fmt.Fprintf(out, "tool calls:     %d\n", res.ToolCalls)
	fmt.Fprintf(out, "tokens:         %d prompt, %d completion\n", res.PromptTokens, res.CompletionTokens)
	if res.WorkDir != "" {
		fmt.Fprintf(out, "workdir:        %s\n", res.WorkDir)
	}
	return 0
}

func checkBinary(name string) error {
	if strings.ContainsRune(name, filepath.Separator) {
		info, err := os.Stat(name)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return errors.New("is a directory")
		}
		return nil
	}
	_, err := exec.LookPath(name)
	return err
}

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "cairnwatch — defensive email and DNS investigation harness")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  cairnwatch run --email <file> --case <dir> --operator <name> --authorized [flags]")
	fmt.Fprintln(w, "  cairnwatch version")
	fmt.Fprintln(w, "  cairnwatch help")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Cairnwatch calls Envelode for metadata-only email parsing, Subsoil for")
	fmt.Fprintln(w, "passive-only DNS, and Stratum to preserve evidence and generate reports.")
	fmt.Fprintln(w, "Raw email content is sent to the model only with --send-email-content.")
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}
