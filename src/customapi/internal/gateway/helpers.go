package gateway

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/redstone/customapi/internal/audit"
	"github.com/redstone/customapi/internal/config"
	"github.com/redstone/customapi/internal/policy"
)

// randRead fills b with cryptographically random bytes.
func randRead(b []byte) { _, _ = rand.Read(b) }

// fillRandom is the non-fatal variant used for identifiers.
func fillRandom(b []byte) { _, _ = rand.Read(b) }

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// errorsAs is a tiny wrapper keeping the import surface of proxy.go explicit.
func errorsAs(err error, target any) bool { return errors.As(err, target) }

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

// limiter is a token-bucket rate limiter for one user.
type limiter struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	rate   float64
	burst  float64
	// inflight counts concurrent requests for the concurrency cap.
	inflight int
}

// allow consumes one token from the user's bucket.
func (s *Server) allow(u config.User) bool {
	v, _ := s.limiters.LoadOrStore(u.Name, &limiter{})
	l := v.(*limiter)
	l.mu.Lock()
	defer l.mu.Unlock()

	rate := u.RateLimit
	burst := float64(u.Burst)
	if burst <= 0 {
		burst = rate * 2
		if burst < 1 {
			burst = 1
		}
	}
	now := time.Now()
	if l.rate != rate || l.burst != burst {
		// Configuration changed; adopt it and refill.
		l.rate, l.burst = rate, burst
		l.tokens = burst
		l.last = now
	}
	if l.last.IsZero() {
		l.tokens = burst
		l.last = now
	}
	elapsed := now.Sub(l.last).Seconds()
	l.last = now
	l.tokens += elapsed * l.rate
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

// acquire reserves a concurrency slot, returning a release function.
func (s *Server) acquire(user string, max int) (func(), bool) {
	v, _ := s.limiters.LoadOrStore(user, &limiter{})
	l := v.(*limiter)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.inflight >= max {
		return nil, false
	}
	l.inflight++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			l.inflight--
			l.mu.Unlock()
		})
	}, true
}

// ---------------------------------------------------------------------------
// Sampling
// ---------------------------------------------------------------------------

// sampleWanted reports whether this exchange should carry a redacted excerpt.
//
// Sampling exists so an operator can debug a policy rule without turning the
// audit ledger into a transcript store. It is limited to interesting
// exchanges: anything that produced a finding, a metering anomaly, or an
// error. A clean exchange is never sampled, which keeps the ledger small and
// preserves user privacy by default.
func (s *Server) sampleWanted(pc *proxyContext) bool {
	if pc.decision == audit.DecisionAllow && !pc.deviation.OverThreshold {
		return false
	}
	return len(pc.outboundDecision.Findings) > 0 ||
		len(pc.inboundDecision.Findings) > 0 ||
		pc.deviation.OverThreshold ||
		pc.decision != audit.DecisionAllow
}

// maxSampleBytes bounds a redacted excerpt.
const maxSampleBytes = 2048

// buildSample renders a redacted request/response excerpt.
func (s *Server) buildSample(pc *proxyContext) *audit.Sample {
	note := "sampled for operator review"
	if f, ok := pc.inboundDecision.Highest(); ok {
		note = "inbound rule " + f.Rule
	} else if f, ok := pc.outboundDecision.Highest(); ok {
		note = "outbound rule " + f.Rule
	} else if pc.deviation.OverThreshold {
		note = "usage deviation flagged"
	} else if pc.decision != audit.DecisionAllow {
		note = string(pc.decision)
	}
	return &audit.Sample{
		RequestText:  sampleExcerpt(pc.body, s.redactor),
		ResponseText: "", // filled by the streaming/buffered path when available
		Note:         note,
	}
}

// sampleExcerpt truncates and redacts a body for storage.
func sampleExcerpt(body []byte, r *policy.Redactor) string {
	if len(body) == 0 {
		return ""
	}
	b := body
	if len(b) > maxSampleBytes {
		b = b[:maxSampleBytes]
	}
	return redactString(r, string(b))
}

func redactString(r *policy.Redactor, s string) string {
	if r == nil {
		return s
	}
	return r.Redact(s)
}
