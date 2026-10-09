package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/theretechlabs/retech-authkit/clientip"
	"github.com/theretechlabs/retech-authkit/ratelimit"
)

// RateLimiter é o limitador de janela fixa do retech-authkit (por chave, em
// memória, por instância).
type RateLimiter = ratelimit.Limiter

// NewRateLimiter cria um limitador de `limit` eventos por `window` por chave.
// limit <= 0 desliga.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return ratelimit.New(limit, window)
}

// RateLimit responde 429 (com Retry-After) quando a chave estoura o limite.
func RateLimit(l *RateLimiter, keyFn func(*gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !l.Enabled() {
			c.Next()
			return
		}
		ok, retry := l.Allow(keyFn(c))
		if !ok {
			c.Header("Retry-After", ratelimit.RetryAfterSeconds(retry))
			respondWithError(c, http.StatusTooManyRequests, "Muitas tentativas. Tente novamente em instantes.")
			return
		}
		c.Next()
	}
}

// ClientIP devolve o IP do cliente pelo ÚLTIMO hop de X-Forwarded-For.
func ClientIP(r *http.Request) string { return clientip.FromRequest(r) }

// KeyByClientIP é o keyFn padrão (IP do cliente).
func KeyByClientIP(c *gin.Context) string { return ClientIP(c.Request) }
