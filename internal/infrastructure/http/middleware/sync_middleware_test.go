package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/theretechlabs/retech-authkit/hmacsig"
)

const testSecret = "segredo-de-teste-nao-usar-em-producao"

func newSyncRouter(secret string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/sync", NewSyncMiddleware(secret).AuthenticateSync(), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	return r
}

func signedRequest(t *testing.T, body []byte, secret string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/sync", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if err := hmacsig.SignRequest(req, body, secret, time.Now()); err != nil {
		t.Fatal(err)
	}
	return req
}

func serve(r *gin.Engine, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestSyncMiddleware_HMACValidoPassaEReplayRejeita(t *testing.T) {
	r := newSyncRouter(testSecret)
	body := []byte(`{"code":"app"}`)
	req := signedRequest(t, body, testSecret)
	if w := serve(r, req); w.Code != http.StatusOK {
		t.Fatalf("esperava 200, obteve %d: %s", w.Code, w.Body.String())
	}
	// Mesmos headers (mesmo nonce) de novo: replay.
	req2 := httptest.NewRequest(http.MethodPost, "/sync", bytes.NewReader(body))
	req2.Header = req.Header.Clone()
	if w := serve(r, req2); w.Code != http.StatusUnauthorized {
		t.Fatalf("replay esperava 401, obteve %d", w.Code)
	}
}

func TestSyncMiddleware_SemHMACRejeitaMesmoComBearer(t *testing.T) {
	// Regressão: antes, sem X-Signature o middleware caía num fallback JWT e
	// qualquer usuário final autenticado conseguia chamar /sync e /password-reset.
	req := httptest.NewRequest(http.MethodPost, "/sync", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer qualquer-token")
	if w := serve(newSyncRouter(testSecret), req); w.Code != http.StatusUnauthorized {
		t.Fatalf("esperava 401 sem HMAC, obteve %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncMiddleware_SemNonceOuAssinaturaErradaRejeita(t *testing.T) {
	r := newSyncRouter(testSecret)
	body := []byte(`{"code":"app"}`)
	req := signedRequest(t, body, testSecret)
	req.Header.Del("X-Nonce")
	if w := serve(r, req); w.Code != http.StatusUnauthorized {
		t.Fatalf("sem nonce esperava 401, obteve %d", w.Code)
	}
	req = signedRequest(t, body, "outro-secret")
	w := serve(r, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("assinatura errada esperava 401, obteve %d", w.Code)
	}
	if bytes.Contains(w.Body.Bytes(), []byte("nonce")) || bytes.Contains(w.Body.Bytes(), []byte("timestamp")) {
		t.Fatalf("resposta não deve detalhar o motivo: %s", w.Body.String())
	}
}

func TestSyncMiddleware_SemSecretConfigurado503(t *testing.T) {
	body := []byte(`{"code":"app"}`)
	if w := serve(newSyncRouter(""), signedRequest(t, body, "x")); w.Code != http.StatusServiceUnavailable {
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
	if w := serve(r, signedRequest(t, body, testSecret)); w.Code != http.StatusOK {
		t.Fatalf("esperava 200, obteve %d", w.Code)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("handler recebeu body diferente: %q", got)
	}
}
