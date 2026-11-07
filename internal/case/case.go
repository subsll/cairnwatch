// Package case wraps the Stratum CLI for case setup and reporting.
package stratumcase

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Run executes a Stratum command and returns combined output.
func Run(ctx context.Context, stratum string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, stratum, args...)
	data, err := cmd.CombinedOutput()
	if err != nil {
		if cctx.Err() == context.DeadlineExceeded {
			return string(data), fmt.Errorf("stratum timed out")
		}
		return string(data), fmt.Errorf("stratum %s: %w: %s", strings.Join(args, " "), err, truncate(string(data), 800))
	}
	return string(data), nil
}

// Init creates a Stratum case at dir.
func Init(ctx context.Context, stratum, dir, name, examiner, org string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	args := []string{"init", name, "--dir", dir, "--examiner", examiner, "--no-register"}
	if org != "" {
		args = append(args, "--org", org)
	}
	_, err := Run(ctx, stratum, args...)
	return err
}

// Add preserves a file or directory in the case.
func Add(ctx context.Context, stratum, caseDir, path, origin, note string) error {
	args := []string{"add", path, "-w", caseDir, "--origin", origin}
	if note != "" {
		args = append(args, "--note", note)
	}
	_, err := Run(ctx, stratum, args...)
	return err
}

// Report renders Stratum's own report set.
func Report(ctx context.Context, stratum, caseDir, outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	_, err := Run(ctx, stratum, "report", "-w", caseDir, "-f", "markdown,json", "-o", outDir)
	return err
}

// Verify checks both hash chains and re-hashes evidence.
func Verify(ctx context.Context, stratum, caseDir string) (string, error) {
	return Run(ctx, stratum, "verify", "-w", caseDir)
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
