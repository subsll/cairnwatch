// Package progress provides a small terminal spinner.
package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

var frames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// IsTerminal reports whether f is a character device.
func IsTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// Spinner renders one mutable status line on w.
type Spinner struct {
	w       io.Writer
	enabled bool

	mu      sync.Mutex
	label   string
	start   time.Time
	frame   int
	running bool
	stopped bool
	stopCh  chan struct{}
	doneCh  chan struct{}
}

// New returns a spinner. No output is produced when enabled is false.
func New(w io.Writer, enabled bool) *Spinner {
	return &Spinner{w: w, enabled: enabled}
}

// Start begins the spinner with a label.
func (s *Spinner) Start(label string) {
	if s == nil || !s.enabled {
		return
	}
	s.mu.Lock()
	if s.running || s.stopped {
		s.label = label
		s.mu.Unlock()
		return
	}
	s.label = label
	s.start = time.Now()
	s.running = true
	s.stopCh = make(chan struct{})
	s.doneCh = make(chan struct{})
	s.renderLocked()
	s.mu.Unlock()
	go s.loop()
}

// Set changes the current label and redraws immediately.
func (s *Spinner) Set(label string) {
	if s == nil || !s.enabled {
		return
	}
	s.mu.Lock()
	if !s.stopped {
		s.label = label
		if s.running {
			s.renderLocked()
		}
	}
	s.mu.Unlock()
}

// Stop clears the line and stops rendering. It is safe to call repeatedly.
func (s *Spinner) Stop() {
	if s == nil || !s.enabled {
		return
	}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	s.running = false
	if s.stopCh != nil {
		close(s.stopCh)
	}
	done := s.doneCh
	s.mu.Unlock()
	if done != nil {
		<-done
	}
	s.mu.Lock()
	fmt.Fprint(s.w, "\r\033[2K")
	s.mu.Unlock()
}

func (s *Spinner) loop() {
	defer close(s.doneCh)
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			s.mu.Lock()
			if s.running {
				s.frame = (s.frame + 1) % len(frames)
				s.renderLocked()
			}
			s.mu.Unlock()
		}
	}
}

func (s *Spinner) renderLocked() {
	label := strings.Join(strings.Fields(s.label), " ")
	if label == "" {
		label = "working"
	}
	elapsed := time.Since(s.start).Round(time.Second)
	fmt.Fprintf(s.w, "\r\033[2K%s %s  %s", frames[s.frame], label, elapsed)
}
