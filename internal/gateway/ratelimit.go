package gateway

import (
	"sync"
	"time"
)

// rateLimiter es un token bucket por cliente.
type rateLimiter struct {
	mu      sync.Mutex
	perSec  float64
	burst   float64
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(perMinute float64, burst int) *rateLimiter {
	if perMinute <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	return &rateLimiter{
		perSec:  perMinute / 60,
		burst:   float64(burst),
		buckets: map[string]*bucket{},
		now:     time.Now,
	}
}

// allow devuelve false si el cliente ha agotado su cupo. Con un limitador nil
// siempre permite.
func (rl *rateLimiter) allow(client string) bool {
	if rl == nil {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	b, ok := rl.buckets[client]
	if !ok {
		// Evita crecer sin límite con muchas IPs distintas.
		if len(rl.buckets) > 10000 {
			rl.buckets = map[string]*bucket{}
		}
		b = &bucket{tokens: rl.burst, last: now}
		rl.buckets[client] = b
	}
	b.tokens = min(rl.burst, b.tokens+now.Sub(b.last).Seconds()*rl.perSec)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
