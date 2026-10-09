package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/theretech/retech-auth-api/internal/application/service"
	"github.com/theretech/retech-auth-api/internal/domain/dto"
)

type contextKey string

const (
	UserIDKey        contextKey = "user_id"
	UserEmailKey     contextKey = "user_email"
	ApplicationIDKey contextKey = "application_id"
	TenantIDKey      contextKey = "tenant_id"
)

// AuthMiddleware é o middleware de autenticação
type AuthMiddleware struct {
	jwtService service.JWTService
}

// NewAuthMiddleware cria uma nova instância do middleware de autenticação
func NewAuthMiddleware(jwtService service.JWTService) *AuthMiddleware {
	return &AuthMiddleware{
		jwtService: jwtService,
	}
}

// Authenticate verifica se o usuário está autenticado
func (m *AuthMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			respondWithError(c, http.StatusUnauthorized, "Token de autenticação não fornecido")
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			respondWithError(c, http.StatusUnauthorized, "Formato de token inválido")
			c.Abort()
			return
		}

		tokenString := parts[1]

		// Só access token (typ=access): refresh token não autentica requisições.
		claims, err := m.jwtService.ValidateAccessToken(tokenString)
		if err != nil {
			if err == service.ErrExpiredToken {
				respondWithError(c, http.StatusUnauthorized, "Token expirado")
				c.Abort()
				return
			}
			respondWithError(c, http.StatusUnauthorized, "Token inválido")
			c.Abort()
			return
		}

		ctx := c.Request.Context()
		ctx = context.WithValue(ctx, UserIDKey, claims.UserID)
		ctx = context.WithValue(ctx, UserEmailKey, claims.Email)
		ctx = context.WithValue(ctx, ApplicationIDKey, claims.ApplicationID)
		if claims.TenantID != nil {
			ctx = context.WithValue(ctx, TenantIDKey, *claims.TenantID)
		}

		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// GetUserID extrai o ID do usuário do contexto
func GetUserID(ctx context.Context) (uuid.UUID, bool) {
	userID, ok := ctx.Value(UserIDKey).(uuid.UUID)
	return userID, ok
}

// GetUserEmail extrai o email do usuário do contexto
func GetUserEmail(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(UserEmailKey).(string)
	return email, ok
}

// GetApplicationID extrai o ID da aplicação do contexto
func GetApplicationID(ctx context.Context) (uuid.UUID, bool) {
	appID, ok := ctx.Value(ApplicationIDKey).(uuid.UUID)
	return appID, ok
}

// GetTenantID extrai o ID do tenant (unidade) do contexto
func GetTenantID(ctx context.Context) (string, bool) {
	tenantID, ok := ctx.Value(TenantIDKey).(string)
	return tenantID, ok
}

func respondWithError(c *gin.Context, code int, message string) {
	c.JSON(code, dto.ErrorResponse{
		Error:   http.StatusText(code),
		Message: message,
		Code:    code,
	})
	c.Abort()
}
