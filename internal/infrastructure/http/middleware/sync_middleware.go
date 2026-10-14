package middleware

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/theretechlabs/retech-authkit/hmacsig"
)

// maxSignedBodyBytes limita o body lido para validação HMAC (manifests são
// pequenos; evita que um cliente anônimo force leitura ilimitada em memória).
const maxSignedBodyBytes = 1 << 20 // 1 MiB

// SyncMiddleware protege rotas internas (serviço → serviço): /applications/sync
// e /password-reset/*. Exige HMAC-SHA256(body || timestamp || nonce) com o
// BOOTSTRAP_SECRET compartilhado (retech-authkit/hmacsig). Sem fallback para
// JWT: um token de usuário final NÃO autoriza criar aplicações/roles/permissões
// nem redefinir senhas. X-Nonce é obrigatório e aceito uma única vez.
type SyncMiddleware struct {
	verifier *hmacsig.Verifier
}

// NewSyncMiddleware cria o middleware de autenticação HMAC para rotas internas.
func NewSyncMiddleware(bootstrapSecret string) *SyncMiddleware {
	return &SyncMiddleware{verifier: hmacsig.NewVerifier(bootstrapSecret)}
}

// AuthenticateSync valida a assinatura HMAC obrigatória (X-Signature, X-Timestamp, X-Nonce).
func (m *SyncMiddleware) AuthenticateSync() gin.HandlerFunc {
	return func(c *gin.Context) {
		body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxSignedBodyBytes))
		if err != nil {
			respondWithError(c, http.StatusBadRequest, "Erro ao ler body da requisição")
			return
		}
		// Restaura o body para o handler.
		c.Request.Body = io.NopCloser(bytes.NewReader(body))

		if err := m.verifier.VerifyRequest(c.Request, body); err != nil {
			if errors.Is(err, hmacsig.ErrNoSecret) {
				// Fail-closed: sem secret configurado a rota interna fica indisponível.
				respondWithError(c, http.StatusServiceUnavailable, "Bootstrap não configurado: BOOTSTRAP_SECRET não definido")
				return
			}
			// Motivo (janela, nonce, replay, assinatura) só no log, nunca na resposta.
			log.Printf("hmac rejeitado em %s %s: %v", c.Request.Method, c.FullPath(), err)
			respondWithError(c, http.StatusUnauthorized, "Assinatura HMAC inválida")
			return
		}
		c.Next()
	}
}
