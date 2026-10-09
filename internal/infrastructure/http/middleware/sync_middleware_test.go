package middleware

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func newSyncRouter(secret string) *gin.Engine {
	return newSyncRouterNonce(secret, false)
}

func newSyncRouterNonce(secret string, requireNonce bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	mw := NewSyncMiddleware(secret, requireNonce)
	r.POST("/sync", mw.AuthenticateSync(), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	return r
}

func doSync(r *gin.Engine, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/sync", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func signedHeaders(body []byte, secret string) map[string]string {
	ts := time.Now().Unix()
	return map[string]string{
		"X-Signature": CalculateHMAC(body, ts, secret),
		"X-Timestamp": fmt.Sprintf("%d", ts),
	}
}

func TestSyncMiddleware_HMACValidoPassa(t *testing.T) {
	body := []byte(`{"code":"app"}`)
	w := doSync(newSyncRouter(testSecret), body, signedHeaders(body, testSecret))
	if w.Code != http.StatusOK {
		t.Fatalf("esperava 200, obteve %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncMiddleware_SemHMACRejeitaMesmoComBearer(t *testing.T) {
	// Regressão: antes, sem X-Signature o middleware caía num fallback JWT e
	// qualquer usuário final autenticado conseguia chamar /sync e /password-reset.
	body := []byte(`{"code":"app"}`)
	w := doSync(newSyncRouter(testSecret), body, map[string]string{
		"Authorization": "Bearer qualquer-token",
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("esperava 401 sem HMAC, obteve %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncMiddleware_SemHeadersRejeita(t *testing.T) {
	w := doSync(newSyncRouter(testSecret), []byte(`{}`), nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("esperava 401, obteve %d", w.Code)
	}
}

func TestSyncMiddleware_AssinaturaErradaRejeitaSemVazarMotivo(t *testing.T) {
	body := []byte(`{"code":"app"}`)
	h := signedHeaders(body, "outro-secret")
	w := doSync(newSyncRouter(testSecret), body, h)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("esperava 401, obteve %d", w.Code)
	}
	if bytes.Contains(w.Body.Bytes(), []byte("timestamp")) {
		t.Fatalf("resposta não deve detalhar o motivo da rejeição: %s", w.Body.String())
	}
}

func TestSyncMiddleware_TimestampForaDaJanelaRejeita(t *testing.T) {
	body := []byte(`{"code":"app"}`)
	ts := time.Now().Add(-10 * time.Minute).Unix()
	w := doSync(newSyncRouter(testSecret), body, map[string]string{
		"X-Signature": CalculateHMAC(body, ts, testSecret),
		"X-Timestamp": fmt.Sprintf("%d", ts),
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("esperava 401, obteve %d", w.Code)
	}
}

func TestSyncMiddleware_TimestampInvalidoRejeita(t *testing.T) {
	body := []byte(`{"code":"app"}`)
	w := doSync(newSyncRouter(testSecret), body, map[string]string{
		"X-Signature": "abc",
		"X-Timestamp": "ontem",
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("esperava 401, obteve %d", w.Code)
	}
}

func TestSyncMiddleware_SemSecretConfigurado503(t *testing.T) {
	body := []byte(`{"code":"app"}`)
	w := doSync(newSyncRouter(""), body, signedHeaders(body, "x"))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("esperava 503, obteve %d", w.Code)
	}
}

func TestSyncMiddleware_BodyChegaIntactoNoHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	var got []byte
	r.POST("/sync", NewSyncMiddleware(testSecret, false).AuthenticateSync(), func(c *gin.Context) {
		got, _ = c.GetRawData()
		c.Status(http.StatusOK)
	})
	body := []byte(`{"code":"app","name":"App"}`)
	w := doSync(r, body, signedHeaders(body, testSecret))
	if w.Code != http.StatusOK {
		t.Fatalf("esperava 200, obteve %d", w.Code)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("handler recebeu body diferente: %q", got)
	}
}

func signedHeadersNonce(body []byte, secret, nonce string) map[string]string {
	ts := time.Now().Unix()
	return map[string]string{
		"X-Signature": CalculateHMACWithNonce(body, ts, nonce, secret),
		"X-Timestamp": fmt.Sprintf("%d", ts),
		"X-Nonce":     nonce,
	}
}

func TestSyncMiddleware_NonceValidoPassaEReplayRejeita(t *testing.T) {
	r := newSyncRouterNonce(testSecret, true)
	body := []byte(`{"code":"app"}`)
	h := signedHeadersNonce(body, testSecret, "nonce-0123456789abcdef")

	if w := doSync(r, body, h); w.Code != http.StatusOK {
		t.Fatalf("1ª esperava 200, obteve %d: %s", w.Code, w.Body.String())
	}
	// Mesma requisição (mesmo nonce, mesma assinatura): replay.
	if w := doSync(r, body, h); w.Code != http.StatusUnauthorized {
		t.Fatalf("replay esperava 401, obteve %d", w.Code)
	}
	// Nonce novo: passa.
	if w := doSync(r, body, signedHeadersNonce(body, testSecret, "nonce-fedcba9876543210")); w.Code != http.StatusOK {
		t.Fatalf("nonce novo esperava 200, obteve %d", w.Code)
	}
}

func TestSyncMiddleware_NonceForaDaAssinaturaRejeita(t *testing.T) {
	r := newSyncRouterNonce(testSecret, true)
	body := []byte(`{"code":"app"}`)
	// Assinado sem nonce, mas header X-Nonce enviado: o nonce precisa entrar no MAC.
	h := signedHeaders(body, testSecret)
	h["X-Nonce"] = "nonce-0123456789abcdef"
	if w := doSync(r, body, h); w.Code != http.StatusUnauthorized {
		t.Fatalf("esperava 401, obteve %d", w.Code)
	}
}

func TestSyncMiddleware_NonceObrigatorioQuandoConfigurado(t *testing.T) {
	body := []byte(`{"code":"app"}`)
	// Transição (requireNonce=false): cliente sem nonce passa.
	if w := doSync(newSyncRouterNonce(testSecret, false), body, signedHeaders(body, testSecret)); w.Code != http.StatusOK {
		t.Fatalf("sem nonce em modo transição esperava 200, obteve %d", w.Code)
	}
	// Estrito: sem nonce = 401.
	if w := doSync(newSyncRouterNonce(testSecret, true), body, signedHeaders(body, testSecret)); w.Code != http.StatusUnauthorized {
		t.Fatalf("sem nonce em modo estrito esperava 401, obteve %d", w.Code)
	}
	// Nonce curto demais.
	if w := doSync(newSyncRouterNonce(testSecret, true), body, signedHeadersNonce(body, testSecret, "curto")); w.Code != http.StatusUnauthorized {
		t.Fatalf("nonce curto esperava 401, obteve %d", w.Code)
	}
}

func TestNonceStore_ExpiraAposTTL(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	s := NewNonceStore(time.Minute)
	s.now = func() time.Time { return now }
	if !s.Remember("n1") || s.Remember("n1") {
		t.Fatal("primeira vez true, segunda false")
	}
	now = now.Add(2 * time.Minute)
	if !s.Remember("n1") {
		t.Fatal("após o TTL o nonce pode voltar a ser usado (fora da janela do timestamp)")
	}
}
