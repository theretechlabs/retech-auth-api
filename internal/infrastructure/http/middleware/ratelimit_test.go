package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestRateLimit_429ComRetryAfterEIPDoUltimoHop(t *testing.T) {
	r := newTestEngine()
	r.POST("/login", RateLimit(NewRateLimiter(1, time.Minute), KeyByClientIP), func(c *gin.Context) { c.Status(http.StatusOK) })

	do := func(xff string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		req.Header.Set("X-Forwarded-For", xff)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	if w := do("203.0.113.9"); w.Code != http.StatusOK {
		t.Fatalf("1ª esperava 200, obteve %d", w.Code)
	}
	w := do("203.0.113.9")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("2ª esperava 429 com Retry-After, obteve %d %q", w.Code, w.Header().Get("Retry-After"))
	}
	// Primeiro hop do XFF é controlado pelo cliente: mudar ele NÃO burla o limite.
	if w := do("1.2.3.4, 203.0.113.9"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("spoof do primeiro hop deveria continuar bloqueado, obteve %d", w.Code)
	}
}

func TestRateLimit_Desligado(t *testing.T) {
	r := newTestEngine()
	r.POST("/x", RateLimit(NewRateLimiter(0, time.Minute), KeyByClientIP), func(c *gin.Context) { c.Status(http.StatusOK) })
	for i := 0; i < 50; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/x", nil))
		if w.Code != http.StatusOK {
			t.Fatal("limitador desligado nunca bloqueia")
		}
	}
}
