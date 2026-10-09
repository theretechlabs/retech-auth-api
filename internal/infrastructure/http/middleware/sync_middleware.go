package middleware

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// maxSignedBodyBytes limita o body lido para validação HMAC (manifests são
// pequenos; evita que um cliente anônimo force leitura ilimitada em memória).
const maxSignedBodyBytes = 1 << 20 // 1 MiB

// Tamanho aceito para X-Nonce (string opaca, aleatória).
const (
	minNonceLen = 16
	maxNonceLen = 128
)

// SyncMiddleware protege rotas internas (serviço → serviço): /applications/sync
// e /password-reset/*. Exige HMAC-SHA256(body+timestamp) com o BOOTSTRAP_SECRET
// compartilhado. Não há fallback para JWT: um token de usuário final de qualquer
// aplicação NÃO autoriza criar aplicações/roles/permissões nem redefinir senhas.
//
// Anti-replay: além da janela do X-Timestamp, o cliente envia X-Nonce (aleatório,
// entra na assinatura) e um nonce só é aceito uma vez dentro da janela. Com
// requireNonce=false clientes sem nonce ainda passam (transição); true exige.
type SyncMiddleware struct {
	bootstrapSecret string
	requireNonce    bool
	nonces          *NonceStore
}

// NewSyncMiddleware cria o middleware de autenticação HMAC para rotas internas.
func NewSyncMiddleware(bootstrapSecret string, requireNonce bool) *SyncMiddleware {
	return &SyncMiddleware{
		bootstrapSecret: bootstrapSecret,
		requireNonce:    requireNonce,
		nonces:          NewNonceStore(hmacMaxAge + hmacSkew),
	}
}

// AuthenticateSync valida a assinatura HMAC obrigatória (X-Signature + X-Timestamp).
func (m *SyncMiddleware) AuthenticateSync() gin.HandlerFunc {
	return func(c *gin.Context) {
		if m.bootstrapSecret == "" {
			// Fail-closed: sem secret configurado a rota interna fica indisponível.
			respondWithError(c, http.StatusServiceUnavailable, "Bootstrap não configurado: BOOTSTRAP_SECRET não definido")
			return
		}

		signature := c.GetHeader("X-Signature")
		timestampStr := c.GetHeader("X-Timestamp")
		nonce := c.GetHeader("X-Nonce")
		if signature == "" || timestampStr == "" {
			respondWithError(c, http.StatusUnauthorized, "Assinatura HMAC obrigatória: envie X-Signature, X-Timestamp e X-Nonce")
			return
		}
		if nonce == "" && m.requireNonce {
			respondWithError(c, http.StatusUnauthorized, "Assinatura HMAC obrigatória: envie X-Nonce")
			return
		}
		if nonce != "" && (len(nonce) < minNonceLen || len(nonce) > maxNonceLen) {
			respondWithError(c, http.StatusUnauthorized, "Assinatura HMAC inválida")
			return
		}

		timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
		if err != nil {
			respondWithError(c, http.StatusUnauthorized, "Assinatura HMAC inválida")
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxSignedBodyBytes))
		if err != nil {
			respondWithError(c, http.StatusBadRequest, "Erro ao ler body da requisição")
			return
		}
		// Restaura o body para o handler.
		c.Request.Body = io.NopCloser(bytes.NewReader(body))

		if err := ValidateHMACWithNonce(body, timestamp, nonce, signature, m.bootstrapSecret); err != nil {
			// Detalhe (timestamp fora da janela vs assinatura errada) só no log,
			// nunca na resposta.
			log.Printf("hmac rejeitado em %s %s: %v", c.Request.Method, c.FullPath(), err)
			respondWithError(c, http.StatusUnauthorized, "Assinatura HMAC inválida")
			return
		}
		// Só depois da assinatura válida: nonce não assinado não polui o store.
		if nonce != "" && !m.nonces.Remember(nonce) {
			log.Printf("hmac replay (nonce repetido) em %s %s", c.Request.Method, c.FullPath())
			respondWithError(c, http.StatusUnauthorized, "Assinatura HMAC inválida")
			return
		}

		c.Next()
	}
}
