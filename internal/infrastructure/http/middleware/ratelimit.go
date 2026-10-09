package middleware

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter é um limitador de janela fixa em memória (por chave). Serve para
// uma instância; com réplicas o limite vale por réplica. Zero alocação externa.
type RateLimiter struct {
	limit  int
	window time.Duration
	now    func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
	sweeps  int
}

type bucket struct {
	count   int
	resetAt time.Time
}

// maxBuckets força uma varredura de chaves expiradas quando o mapa cresce.
const maxBuckets = 10000

// NewRateLimiter cria um limitador de `limit` eventos por `window` por chave.
// limit <= 0 desliga (Allow sempre true).
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{limit: limit, window: window, now: time.Now, buckets: make(map[string]*bucket)}
}

// Enabled informa se o limitador está ativo.
func (l *RateLimiter) Enabled() bool { return l != nil && l.limit > 0 }

// Allow consome um evento da chave. Quando bloqueado devolve o tempo até a janela zerar.
func (l *RateLimiter) Allow(key string) (bool, time.Duration) {
	if !l.Enabled() {
		return true, 0
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok || !now.Before(b.resetAt) {
		if len(l.buckets) >= maxBuckets {
			l.sweep(now)
		}
		l.buckets[key] = &bucket{count: 1, resetAt: now.Add(l.window)}
		return true, 0
	}
	if b.count >= l.limit {
		return false, b.resetAt.Sub(now)
	}
	b.count++
	return true, 0
}

func (l *RateLimiter) sweep(now time.Time) {
	for k, b := range l.buckets {
		if !now.Before(b.resetAt) {
			delete(l.buckets, k)
		}
	}
	l.sweeps++
}

// Middleware responde 429 (com Retry-After) quando a chave estoura o limite.
func (l *RateLimiter) Middleware(keyFn func(*gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !l.Enabled() {
			c.Next()
			return
		}
		ok, retry := l.Allow(keyFn(c))
		if !ok {
			secs := int(retry.Seconds())
			if secs < 1 {
				secs = 1
			}
			c.Header("Retry-After", strconv.Itoa(secs))
			respondWithError(c, http.StatusTooManyRequests, "Muitas tentativas. Tente novamente em instantes.")
			return
		}
		c.Next()
	}
}

// ClientIP devolve o IP do cliente pelo ÚLTIMO hop de X-Forwarded-For (o
// primeiro é controlado pelo cliente e permitiria burlar o limite), depois
// X-Real-IP, depois RemoteAddr.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// KeyByClientIP é o keyFn padrão (IP do cliente).
func KeyByClientIP(c *gin.Context) string { return ClientIP(c.Request) }
