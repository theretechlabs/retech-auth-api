package service

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrInvalidToken = errors.New("token inválido")
	ErrExpiredToken = errors.New("token expirado")
	// ErrWrongTokenType indica que o token é válido mas não é do tipo esperado
	// (ex.: refresh token usado como access token).
	ErrWrongTokenType = errors.New("tipo de token inesperado")
)

// Tipos de token (claim `typ`). Access e refresh nunca são intercambiáveis.
const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
)

// DefaultIssuer é o `iss` padrão quando JWT_ISSUER não está definido.
const DefaultIssuer = "retech-auth-api"

// Claims representa as claims do JWT
type Claims struct {
	// Sub (Subject) - padrão JWT para identificar o usuário
	Sub           string    `json:"sub"`     // user_id como string (padrão JWT)
	UserID        uuid.UUID `json:"user_id"` // Mantido para compatibilidade
	Email         string    `json:"email"`
	Name          string    `json:"name,omitempty"` // Nome do usuário (para desnormalização controlada em auditoria)
	ApplicationID uuid.UUID `json:"application_id"`
	TenantID      *string   `json:"tenant_id,omitempty"` // ID da unidade (tenant). Carregado do banco e incluído no token.
	Roles         []string  `json:"roles,omitempty"`     // Array de role codes (ex: ["master", "core_admin"]). Usado para autorização e multi-tenancy hierárquico.
	Perms         []string  `json:"perms,omitempty"`     // Codes das permissions efetivas ("subject:action"; master = ["all:manage"]). Permite enforcement stateless nas APIs de recurso.
	// Typ distingue access de refresh ("access" | "refresh").
	Typ string `json:"typ"`
	// RegisteredClaims carrega iss, aud (= application_code), jti, exp, iat, nbf.
	jwt.RegisteredClaims
}

// TokenSubject é o que entra num par de tokens.
type TokenSubject struct {
	UserID          uuid.UUID
	ApplicationID   uuid.UUID
	ApplicationCode string // vira o claim `aud`
	Email           string
	Name            string
	TenantID        *string
	Roles           []string
	Perms           []string // só no access token
}

// IssuedToken é um refresh token emitido, com o `jti` que deve ser persistido.
type IssuedToken struct {
	Token     string
	JTI       uuid.UUID
	ExpiresAt time.Time
}

// JWTService fornece métodos para geração e validação de tokens JWT
type JWTService interface {
	GenerateAccessToken(s TokenSubject) (string, error)
	GenerateRefreshToken(s TokenSubject) (IssuedToken, error)
	// ValidateToken valida assinatura, iss e validade, sem checar o tipo.
	ValidateToken(tokenString string) (*Claims, error)
	// ValidateAccessToken é ValidateToken + typ=access.
	ValidateAccessToken(tokenString string) (*Claims, error)
	// ValidateRefreshToken é ValidateToken + typ=refresh + jti presente.
	ValidateRefreshToken(tokenString string) (*Claims, error)
	GetExpirationTime() int
	GetJWKS() (map[string]interface{}, error)
}

type jwtService struct {
	rsaKeyService RSAKeyService
	accessTTL     time.Duration
	refreshTTL    time.Duration
	issuer        string
}

// NewJWTService cria uma nova instância de JWTService usando chaves RSA.
// accessTTL/refreshTTL são as validades dos tokens (ver JWTConfig.AccessTokenTTL).
// issuer vazio usa DefaultIssuer.
func NewJWTService(rsaKeyService RSAKeyService, accessTTL, refreshTTL time.Duration, issuer string) JWTService {
	if issuer == "" {
		issuer = DefaultIssuer
	}
	return &jwtService{
		rsaKeyService: rsaKeyService,
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
		issuer:        issuer,
	}
}

func (s *jwtService) registered(s2 TokenSubject, ttl time.Duration, now time.Time) jwt.RegisteredClaims {
	rc := jwt.RegisteredClaims{
		Issuer:    s.issuer,
		Subject:   s2.UserID.String(),
		ID:        uuid.NewString(),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
	}
	if s2.ApplicationCode != "" {
		rc.Audience = jwt.ClaimStrings{s2.ApplicationCode}
	}
	return rc
}

func (s *jwtService) sign(claims *Claims) (string, error) {
	kid := s.rsaKeyService.GetCurrentKeyID()
	privateKey, err := s.rsaKeyService.GetPrivateKey(kid)
	if err != nil {
		return "", fmt.Errorf("erro ao obter chave privada: %w", err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	return token.SignedString(privateKey)
}

// GenerateAccessToken gera um token de acesso usando RS256.
// perms carrega os codes das permissions efetivas ("subject:action") para
// enforcement stateless nas APIs de recurso; o refresh token não os carrega
// (são recalculados a cada refresh).
func (s *jwtService) GenerateAccessToken(sub TokenSubject) (string, error) {
	now := time.Now()
	claims := &Claims{
		Sub:              sub.UserID.String(),
		UserID:           sub.UserID,
		Email:            sub.Email,
		Name:             sub.Name,
		ApplicationID:    sub.ApplicationID,
		TenantID:         sub.TenantID,
		Roles:            sub.Roles,
		Perms:            sub.Perms,
		Typ:              TokenTypeAccess,
		RegisteredClaims: s.registered(sub, s.accessTTL, now),
	}
	return s.sign(claims)
}

// GenerateRefreshToken gera um token de renovação usando RS256. O `jti`
// devolvido deve ser persistido (refresh_tokens) para rotação e revogação.
func (s *jwtService) GenerateRefreshToken(sub TokenSubject) (IssuedToken, error) {
	now := time.Now()
	claims := &Claims{
		Sub:              sub.UserID.String(),
		UserID:           sub.UserID,
		Email:            sub.Email,
		Name:             sub.Name,
		ApplicationID:    sub.ApplicationID,
		TenantID:         sub.TenantID,
		Roles:            sub.Roles,
		Typ:              TokenTypeRefresh,
		RegisteredClaims: s.registered(sub, s.refreshTTL, now),
	}
	token, err := s.sign(claims)
	if err != nil {
		return IssuedToken{}, err
	}
	jti, err := uuid.Parse(claims.ID)
	if err != nil {
		return IssuedToken{}, err
	}
	return IssuedToken{Token: token, JTI: jti, ExpiresAt: claims.ExpiresAt.Time}, nil
}

// ValidateToken valida e decodifica um token JWT usando chave pública RSA
func (s *jwtService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verifica que o algoritmo é RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("método de assinatura inesperado: %v", token.Header["alg"])
		}

		// Extrai kid do header (se disponível)
		var kid string
		if kidValue, ok := token.Header["kid"]; ok {
			if kidStr, ok := kidValue.(string); ok {
				kid = kidStr
			}
		}

		// Obtém chave pública (tenta com kid específico, senão usa chave atual)
		publicKey, err := s.rsaKeyService.GetPublicKey(kid)
		if err != nil && kid != "" {
			// Se falhou com kid específico, tenta com chave atual (para tokens antigos)
			publicKey, err = s.rsaKeyService.GetPublicKey("")
		}
		if err != nil {
			return nil, fmt.Errorf("erro ao obter chave pública: %w", err)
		}

		return publicKey, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(s.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrInvalidToken
}

// ValidateAccessToken valida o token e exige typ=access.
func (s *jwtService) ValidateAccessToken(tokenString string) (*Claims, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}
	if claims.Typ != TokenTypeAccess {
		return nil, ErrWrongTokenType
	}
	return claims, nil
}

// ValidateRefreshToken valida o token e exige typ=refresh com jti.
func (s *jwtService) ValidateRefreshToken(tokenString string) (*Claims, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}
	if claims.Typ != TokenTypeRefresh {
		return nil, ErrWrongTokenType
	}
	if _, err := uuid.Parse(claims.ID); err != nil {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// GetExpirationTime retorna o tempo de expiração em segundos
func (s *jwtService) GetExpirationTime() int {
	return int(s.accessTTL.Seconds())
}

// GetJWKS retorna o JSON Web Key Set (JWKS) com chaves públicas RSA
// Permite que clientes validem tokens JWT assinados com RS256
func (s *jwtService) GetJWKS() (map[string]interface{}, error) {
	// Obtém todas as chaves públicas no formato JWK
	jwks, err := s.rsaKeyService.GetAllPublicKeysJWK()
	if err != nil {
		return nil, fmt.Errorf("erro ao obter chaves públicas: %w", err)
	}

	return map[string]interface{}{
		"keys": jwks,
	}, nil
}
