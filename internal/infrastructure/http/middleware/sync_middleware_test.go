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
	gin.SetMode(gin.TestMode)
	r := gin.New()
	mw := NewSyncMiddleware(secret)
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
	r.POST("/sync", NewSyncMiddleware(testSecret).AuthenticateSync(), func(c *gin.Context) {
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
