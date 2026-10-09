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

// SyncMiddleware protege rotas internas (serviço → serviço): /applications/sync
// e /password-reset/*. Exige HMAC-SHA256(body+timestamp) com o BOOTSTRAP_SECRET
// compartilhado. Não há fallback para JWT: um token de usuário final de qualquer
// aplicação NÃO autoriza criar aplicações/roles/permissões nem redefinir senhas.
type SyncMiddleware struct {
	bootstrapSecret string
}

// NewSyncMiddleware cria o middleware de autenticação HMAC para rotas internas.
func NewSyncMiddleware(bootstrapSecret string) *SyncMiddleware {
	return &SyncMiddleware{bootstrapSecret: bootstrapSecret}
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
		if signature == "" || timestampStr == "" {
			respondWithError(c, http.StatusUnauthorized, "Assinatura HMAC obrigatória: envie X-Signature e X-Timestamp")
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

		if err := ValidateHMAC(body, timestamp, signature, m.bootstrapSecret); err != nil {
			// Detalhe (timestamp fora da janela vs assinatura errada) só no log,
			// nunca na resposta.
			log.Printf("hmac rejeitado em %s %s: %v", c.Request.Method, c.FullPath(), err)
			respondWithError(c, http.StatusUnauthorized, "Assinatura HMAC inválida")
			return
		}

		c.Next()
	}
}
