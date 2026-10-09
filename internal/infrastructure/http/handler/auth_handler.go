package handler

import (
	"database/sql"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/theretech/retech-auth-api/internal/application/service"
	"github.com/theretech/retech-auth-api/internal/application/usecase"
	"github.com/theretech/retech-auth-api/internal/domain/dto"
	"github.com/theretech/retech-auth-api/internal/infrastructure/http/middleware"
	"github.com/theretech/retech-auth-api/internal/version"
)

// AuthHandler gerencia as requisições de autenticação
type AuthHandler struct {
	authenticateUseCase *usecase.AuthenticateUseCase
	refreshTokenUseCase *usecase.RefreshTokenUseCase
	logoutUseCase       *usecase.LogoutUseCase
	getUserInfoUseCase  *usecase.GetUserInfoUseCase
	jwtService          service.JWTService
	db                  *sql.DB
	// loginByEmail limita tentativas de login por e-mail (mesmo vindo de IPs diferentes).
	// nil = desligado.
	loginByEmail *middleware.RateLimiter
}

// NewAuthHandler cria uma nova instância de AuthHandler
func NewAuthHandler(
	authenticateUseCase *usecase.AuthenticateUseCase,
	refreshTokenUseCase *usecase.RefreshTokenUseCase,
	logoutUseCase *usecase.LogoutUseCase,
	getUserInfoUseCase *usecase.GetUserInfoUseCase,
	jwtService service.JWTService,
	db *sql.DB,
	loginByEmail *middleware.RateLimiter,
) *AuthHandler {
	return &AuthHandler{
		authenticateUseCase: authenticateUseCase,
		refreshTokenUseCase: refreshTokenUseCase,
		logoutUseCase:       logoutUseCase,
		getUserInfoUseCase:  getUserInfoUseCase,
		jwtService:          jwtService,
		db:                  db,
		loginByEmail:        loginByEmail,
	}
}

// Authenticate manipula a requisição de autenticação
func (h *AuthHandler) Authenticate(c *gin.Context) {
	clientIP := c.ClientIP()
	var req dto.AuthenticateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[auth] POST /authenticate 400 corpo_json_inválido ip=%s err=%v", clientIP, err)
		respondWithError(c, http.StatusBadRequest, "Corpo da requisição inválido")
		return
	}

	if req.Email == "" || req.Password == "" || req.ApplicationCode == "" {
		log.Printf(
			"[auth] POST /authenticate 400 campos_obrigatórios ip=%s email_vazio=%t senha_vazia=%t application_code_vazio=%t",
			clientIP, req.Email == "", req.Password == "", req.ApplicationCode == "",
		)
		respondWithError(c, http.StatusBadRequest, "Email, senha e código da aplicação são obrigatórios")
		return
	}

	// Limite por e-mail: brute force distribuído (vários IPs) numa conta só.
	if ok, retry := h.loginByEmail.Allow(strings.ToLower(strings.TrimSpace(req.Email))); !ok {
		log.Printf("[auth] POST /authenticate 429 limite_por_email ip=%s email=%q", clientIP, req.Email)
		c.Header("Retry-After", strconv.Itoa(max(1, int(retry.Seconds()))))
		respondWithError(c, http.StatusTooManyRequests, "Muitas tentativas para este e-mail. Tente novamente em instantes.")
		return
	}

	response, err := h.authenticateUseCase.Execute(c.Request.Context(), req)
	if err != nil {
		switch err {
		case usecase.ErrInvalidCredentials:
			log.Printf(
				"[auth] POST /authenticate 401 credenciais_inválidas ip=%s email=%q application_code=%q (ver logs [authenticate] para detalhe: usuário/app ou senha)",
				clientIP, req.Email, req.ApplicationCode,
			)
			respondWithError(c, http.StatusUnauthorized, "Credenciais inválidas")
		case usecase.ErrInactiveUser:
			log.Printf("[auth] POST /authenticate 403 usuário_inativo ip=%s email=%q application_code=%q", clientIP, req.Email, req.ApplicationCode)
			respondWithError(c, http.StatusForbidden, "Usuário inativo")
		case usecase.ErrInactiveApp:
			log.Printf("[auth] POST /authenticate 403 aplicação_inativa ip=%s email=%q application_code=%q", clientIP, req.Email, req.ApplicationCode)
			respondWithError(c, http.StatusForbidden, "Aplicação inativa")
		default:
			log.Printf("[auth] POST /authenticate 500 erro_interno ip=%s email=%q application_code=%q err=%v", clientIP, req.Email, req.ApplicationCode, err)
			respondWithError(c, http.StatusInternalServerError, "Erro ao autenticar usuário")
		}
		return
	}

	log.Printf("[auth] POST /authenticate 200 ok ip=%s email=%q application_code=%q user_id=%s", clientIP, req.Email, req.ApplicationCode, response.User.ID)
	respondWithJSON(c, http.StatusOK, response)
}

// Logout revoga o refresh token (e, com all=true, todos os do usuário na aplicação).
// Quem chama é o gateway de sessão do produto; o access token morre pelo exp.
func (h *AuthHandler) Logout(c *gin.Context) {
	var req dto.LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.RefreshToken == "" {
		respondWithError(c, http.StatusBadRequest, "Refresh token é obrigatório")
		return
	}
	if err := h.logoutUseCase.Execute(c.Request.Context(), req.RefreshToken, req.All); err != nil {
		if err == usecase.ErrInvalidRefreshToken {
			respondWithError(c, http.StatusUnauthorized, "Refresh token inválido")
			return
		}
		respondWithError(c, http.StatusInternalServerError, "Erro ao encerrar sessão")
		return
	}
	c.Status(http.StatusNoContent)
}

// RefreshToken manipula a requisição de renovação de token
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req dto.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondWithError(c, http.StatusBadRequest, "Corpo da requisição inválido")
		return
	}

	if req.RefreshToken == "" {
		respondWithError(c, http.StatusBadRequest, "Refresh token é obrigatório")
		return
	}

	response, err := h.refreshTokenUseCase.Execute(c.Request.Context(), req)
	if err != nil {
		switch err {
		case usecase.ErrInvalidRefreshToken:
			respondWithError(c, http.StatusUnauthorized, "Refresh token inválido")
		case usecase.ErrInactiveUser:
			respondWithError(c, http.StatusForbidden, "Usuário inativo")
		default:
			respondWithError(c, http.StatusInternalServerError, "Erro ao renovar token")
		}
		return
	}

	respondWithJSON(c, http.StatusOK, response)
}

// Me manipula a requisição de informações do usuário autenticado
func (h *AuthHandler) Me(c *gin.Context) {
	userID, ok := middleware.GetUserID(c.Request.Context())
	if !ok {
		respondWithError(c, http.StatusUnauthorized, "Usuário não autenticado")
		return
	}

	applicationID, ok := middleware.GetApplicationID(c.Request.Context())
	if !ok {
		respondWithError(c, http.StatusUnauthorized, "Aplicação não identificada")
		return
	}

	response, err := h.getUserInfoUseCase.Execute(c.Request.Context(), userID, applicationID)
	if err != nil {
		switch err {
		case usecase.ErrUserNotFound:
			respondWithError(c, http.StatusNotFound, "Usuário não encontrado")
		default:
			respondWithError(c, http.StatusInternalServerError, "Erro ao buscar informações do usuário")
		}
		return
	}

	respondWithJSON(c, http.StatusOK, response)
}

type healthCheckResponse struct {
	Service  string `json:"service"`
	Status   string `json:"status"`
	DataBase string `json:"dataBase"`
	Version  string `json:"version"`
}

// Health retorna service, status agregado, dataBase (up/down) e version.
func (h *AuthHandler) Health(c *gin.Context) {
	dataBase := "up"
	status := "ok"
	code := http.StatusOK

	if h.db == nil {
		dataBase = "down"
		status = "degraded"
		code = http.StatusServiceUnavailable
	} else if err := h.db.PingContext(c.Request.Context()); err != nil {
		dataBase = "down"
		status = "degraded"
		code = http.StatusServiceUnavailable
	}

	respondWithJSON(c, code, healthCheckResponse{
		Service:  version.Service,
		Status:   status,
		DataBase: dataBase,
		Version:  version.Version,
	})
}

// JWKS retorna o JSON Web Key Set (JWKS) para validação de tokens JWT
// Endpoint padrão da indústria: GET /.well-known/jwks.json
func (h *AuthHandler) JWKS(c *gin.Context) {
	jwks, err := h.jwtService.GetJWKS()
	if err != nil {
		respondWithError(c, http.StatusInternalServerError, "Erro ao gerar JWKS")
		return
	}

	// JWKS deve retornar Content-Type: application/json
	c.Header("Content-Type", "application/json")
	c.JSON(http.StatusOK, jwks)
}
