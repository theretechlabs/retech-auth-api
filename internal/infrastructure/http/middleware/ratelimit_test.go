package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestRateLimiter_BloqueiaAposLimiteELiberaNaProximaJanela(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	l := NewRateLimiter(2, time.Minute)
	l.now = func() time.Time { return now }

	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("1ª deveria passar")
	}
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("2ª deveria passar")
	}
	ok, retry := l.Allow("a")
	if ok {
		t.Fatal("3ª deveria bloquear")
	}
	if retry <= 0 || retry > time.Minute {
		t.Fatalf("retry fora do esperado: %v", retry)
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("outra chave não deveria ser afetada")
	}

	now = now.Add(61 * time.Second)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("nova janela deveria liberar")
	}
}

func TestRateLimiter_Desligado(t *testing.T) {
	l := NewRateLimiter(0, time.Minute)
	for i := 0; i < 100; i++ {
		if ok, _ := l.Allow("x"); !ok {
			t.Fatal("limitador desligado nunca bloqueia")
		}
	}
	var nilLimiter *RateLimiter
	if ok, _ := nilLimiter.Allow("x"); !ok {
		t.Fatal("limitador nil nunca bloqueia")
	}
}

func TestRateLimiter_Middleware429ComRetryAfter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/login", NewRateLimiter(1, time.Minute).Middleware(KeyByClientIP), func(c *gin.Context) { c.Status(http.StatusOK) })

	do := func(xff string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	if w := do("203.0.113.9"); w.Code != http.StatusOK {
		t.Fatalf("1ª esperava 200, obteve %d", w.Code)
	}
	w := do("203.0.113.9")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("2ª esperava 429, obteve %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("esperava Retry-After")
	}
	// Primeiro hop do XFF é controlado pelo cliente: mudar ele NÃO burla o limite.
	if w := do("1.2.3.4, 203.0.113.9"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("spoof do primeiro hop deveria continuar bloqueado, obteve %d", w.Code)
	}
}

func TestClientIP_UltimoHopDoXFF(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	if got := ClientIP(req); got != "10.0.0.1" {
		t.Fatalf("sem headers esperava RemoteAddr, obteve %q", got)
	}
	req.Header.Set("X-Real-IP", "198.51.100.7")
	if got := ClientIP(req); got != "198.51.100.7" {
		t.Fatalf("esperava X-Real-IP, obteve %q", got)
	}
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.9")
	if got := ClientIP(req); got != "203.0.113.9" {
		t.Fatalf("esperava último hop do XFF, obteve %q", got)
	}
}
