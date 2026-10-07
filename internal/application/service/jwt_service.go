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
)

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
	jwt.RegisteredClaims
}

// JWTService fornece métodos para geração e validação de tokens JWT
type JWTService interface {
	GenerateAccessToken(userID, applicationID uuid.UUID, email, name string, tenantID *string, roles, perms []string) (string, error)
	GenerateRefreshToken(userID, applicationID uuid.UUID, email, name string, tenantID *string, roles []string) (string, error)
	ValidateToken(tokenString string) (*Claims, error)
	GetExpirationTime() int
	GetJWKS() (map[string]interface{}, error)
}

type jwtService struct {
	rsaKeyService RSAKeyService
	accessTTL     time.Duration
	refreshTTL    time.Duration
}

// NewJWTService cria uma nova instância de JWTService usando chaves RSA.
// accessTTL/refreshTTL são as validades dos tokens (ver JWTConfig.AccessTokenTTL).
func NewJWTService(rsaKeyService RSAKeyService, accessTTL, refreshTTL time.Duration) JWTService {
	return &jwtService{
		rsaKeyService: rsaKeyService,
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
	}
}

// GenerateAccessToken gera um token de acesso usando RS256.
// perms carrega os codes das permissions efetivas ("subject:action") para
// enforcement stateless nas APIs de recurso; o refresh token não os carrega
// (são recalculados a cada refresh).
func (s *jwtService) GenerateAccessToken(userID, applicationID uuid.UUID, email, name string, tenantID *string, roles, perms []string) (string, error) {
	expirationTime := time.Now().Add(s.accessTTL)
	kid := s.rsaKeyService.GetCurrentKeyID()

	claims := &Claims{
		Sub:           userID.String(), // Padrão JWT (subject)
		UserID:        userID,
		Email:         email,
		Name:          name, // Nome do usuário para desnormalização controlada em auditoria
		ApplicationID: applicationID,
		TenantID:      tenantID,
		Roles:         roles, // Array de role codes para autorização e multi-tenancy hierárquico
		Perms:         perms,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	// Obtém chave privada para assinatura
	privateKey, err := s.rsaKeyService.GetPrivateKey(kid)
	if err != nil {
		return "", fmt.Errorf("erro ao obter chave privada: %w", err)
	}

	// Cria token com RS256
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Adiciona kid no header
	token.Header["kid"] = kid

	return token.SignedString(privateKey)
}

// GenerateRefreshToken gera um token de renovação usando RS256
func (s *jwtService) GenerateRefreshToken(userID, applicationID uuid.UUID, email, name string, tenantID *string, roles []string) (string, error) {
	expirationTime := time.Now().Add(s.refreshTTL)
	kid := s.rsaKeyService.GetCurrentKeyID()

	claims := &Claims{
		Sub:           userID.String(), // Padrão JWT (subject)
		UserID:        userID,
		Email:         email,
		Name:          name, // Nome do usuário para desnormalização controlada em auditoria
		ApplicationID: applicationID,
		TenantID:      tenantID,
		Roles:         roles, // Array de role codes para autorização e multi-tenancy hierárquico
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	// Obtém chave privada para assinatura
	privateKey, err := s.rsaKeyService.GetPrivateKey(kid)
	if err != nil {
		return "", fmt.Errorf("erro ao obter chave privada: %w", err)
	}

	// Cria token com RS256
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Adiciona kid no header
	token.Header["kid"] = kid

	return token.SignedString(privateKey)
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
	})

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
