package main

import (
	"runtime"
	"time"
)

// TokenBucketPacer is a lightweight rate limiter (tokens per second) intended for per-queue pacing.
// ratePPS <= 0 means unlimited.
//
// Notes:
// - Keeps fractional accumulation to avoid systematic under-shoot due to integer truncation.
// - Avoids time.Sleep for very small waits (spin + Gosched) to reduce oversleep at high pps.
type TokenBucketPacer struct {
	ratePPS int64
	burst   int64

	tokens int64

	// lastNs is the timestamp of the last refill, in nanoseconds.
	lastNs int64
	// carry is the fractional part of token accumulation, in [0, 1e9).
	// It represents "ratePPS * elapsedNs mod 1e9".
	carry int64
}

func NewTokenBucketPacer(ratePPS int64, burst int) *TokenBucketPacer {
	if burst <= 0 {
		burst = 1
	}
	nowNs := time.Now().UnixNano()
	p := &TokenBucketPacer{
		ratePPS: ratePPS,
		burst:   int64(burst),
		// Avoid large startup bursts when pacing is enabled.
		tokens: 0,
		lastNs: nowNs,
		carry:  0,
	}
	if ratePPS <= 0 {
		p.tokens = p.burst
	}
	return p
}

func (p *TokenBucketPacer) refill(nowNs int64) {
	if p.ratePPS <= 0 {
		p.tokens = p.burst
		p.lastNs = nowNs
		p.carry = 0
		return
	}
	elapsedNs := nowNs - p.lastNs
	if elapsedNs <= 0 {
		return
	}

	acc := elapsedNs*p.ratePPS + p.carry
	add := acc / int64(time.Second) // tokens to add
	p.carry = acc % int64(time.Second)

	if add <= 0 {
		// Not enough time for a full token yet, but carry has advanced.
		p.lastNs = nowNs
		return
	}

	p.tokens += add
	if p.tokens > p.burst {
		p.tokens = p.burst
	}
	p.lastNs = nowNs
}

// Take returns how many tokens can be consumed now (0..n).
func (p *TokenBucketPacer) Take(n int) int {
	if n <= 0 {
		return 0
	}
	if p.ratePPS <= 0 {
		return n
	}
	nowNs := time.Now().UnixNano()
	p.refill(nowNs)
	if p.tokens <= 0 {
		return 0
	}
	if int64(n) <= p.tokens {
		p.tokens -= int64(n)
		return n
	}
	allowed := int(p.tokens)
	p.tokens = 0
	return allowed
}

// Sleep waits until at least 1 token is likely available.
func (p *TokenBucketPacer) Sleep() {
	if p.ratePPS <= 0 {
		return
	}

	nowNs := time.Now().UnixNano()
	p.refill(nowNs)
	if p.tokens > 0 {
		return
	}

	// Time until the next token based on the fractional carry:
	// needNs = ceil((1e9 - carry) / ratePPS)
	remain := int64(time.Second) - p.carry
	if remain <= 0 {
		runtime.Gosched()
		return
	}
	needNs := (remain + p.ratePPS - 1) / p.ratePPS
	if needNs <= 0 {
		runtime.Gosched()
		return
	}

	sleep := time.Duration(needNs)

	// For very small waits, time.Sleep often over-sleeps and reduces achieved pps.
	// Spin-waiting is more accurate but uses CPU; keep it bounded.
	if sleep <= 200*time.Microsecond {
		deadline := time.Now().Add(sleep)
		for time.Now().Before(deadline) {
			runtime.Gosched()
		}
		return
	}
	time.Sleep(sleep)
}
