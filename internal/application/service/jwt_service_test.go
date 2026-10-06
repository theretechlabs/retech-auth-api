package service

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// newTestJWTService cria RSAKeyService com chave gerada em diretório temporário
// (nenhum banco ou chave do repositório é usado).
func newTestJWTService(t *testing.T) (JWTService, RSAKeyService) {
	t.Helper()

	rsaSvc, err := NewRSAKeyService(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatalf("erro ao criar RSAKeyService: %v", err)
	}

	return NewJWTService(rsaSvc, 1, 2), rsaSvc
}

func TestJWTService_RoundTripAccessToken(t *testing.T) {
	jwtSvc, rsaSvc := newTestJWTService(t)

	userID := uuid.New()
	appID := uuid.New()
	tenant := "tenant-123"
	roles := []string{"master"}
	perms := []string{"all:manage"}

	token, err := jwtSvc.GenerateAccessToken(userID, appID, "user@example.com", "Usuário", &tenant, roles, perms)
	if err != nil {
		t.Fatalf("erro ao gerar access token: %v", err)
	}

	claims, err := jwtSvc.ValidateToken(token)
	if err != nil {
		t.Fatalf("erro ao validar token: %v", err)
	}

	if claims.Sub != userID.String() || claims.UserID != userID {
		t.Errorf("sub/user_id inesperado: sub=%s user_id=%s", claims.Sub, claims.UserID)
	}
	if claims.ApplicationID != appID {
		t.Errorf("application_id inesperado: %s", claims.ApplicationID)
	}
	if claims.Email != "user@example.com" || claims.Name != "Usuário" {
		t.Errorf("email/name inesperados: %s / %s", claims.Email, claims.Name)
	}
	if claims.TenantID == nil || *claims.TenantID != tenant {
		t.Errorf("tenant_id inesperado: %v", claims.TenantID)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "master" {
		t.Errorf("roles inesperadas: %v", claims.Roles)
	}
	if len(claims.Perms) != 1 || claims.Perms[0] != "all:manage" {
		t.Errorf("perms inesperadas: %v", claims.Perms)
	}

	// Header deve carregar o kid da chave ativa
	parsed, _, err := jwt.NewParser().ParseUnverified(token, &Claims{})
	if err != nil {
		t.Fatalf("erro ao parsear header: %v", err)
	}
	if kid, _ := parsed.Header["kid"].(string); kid != rsaSvc.GetCurrentKeyID() {
		t.Errorf("kid inesperado: %q (esperado %q)", kid, rsaSvc.GetCurrentKeyID())
	}
}

func TestJWTService_RefreshTokenNaoCarregaPerms(t *testing.T) {
	jwtSvc, _ := newTestJWTService(t)

	token, err := jwtSvc.GenerateRefreshToken(uuid.New(), uuid.New(), "u@example.com", "U", nil, []string{"viewer"})
	if err != nil {
		t.Fatalf("erro ao gerar refresh token: %v", err)
	}

	claims, err := jwtSvc.ValidateToken(token)
	if err != nil {
		t.Fatalf("erro ao validar refresh token: %v", err)
	}
	if len(claims.Perms) != 0 {
		t.Errorf("refresh token não deveria carregar perms, obteve %v", claims.Perms)
	}
	if claims.TenantID != nil {
		t.Errorf("tenant_id deveria ser nil, obteve %v", *claims.TenantID)
	}
}

func TestJWTService_TokenAdulteradoRejeitado(t *testing.T) {
	jwtSvc, _ := newTestJWTService(t)

	token, err := jwtSvc.GenerateAccessToken(uuid.New(), uuid.New(), "u@example.com", "U", nil, nil, nil)
	if err != nil {
		t.Fatalf("erro ao gerar token: %v", err)
	}

	// Troca um caractere no meio da assinatura (o último caractere base64url
	// pode não alterar os bytes decodificados por causa dos bits de padding).
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token com formato inesperado: %d partes", len(parts))
	}
	sig := []byte(parts[2])
	mid := len(sig) / 2
	if sig[mid] == 'A' {
		sig[mid] = 'B'
	} else {
		sig[mid] = 'A'
	}
	tampered := parts[0] + "." + parts[1] + "." + string(sig)

	if _, err := jwtSvc.ValidateToken(tampered); err != ErrInvalidToken {
		t.Fatalf("esperava ErrInvalidToken, obteve %v", err)
	}
}

func TestJWTService_TokenDeOutraChaveRejeitado(t *testing.T) {
	jwtSvcA, _ := newTestJWTService(t)
	jwtSvcB, _ := newTestJWTService(t)

	token, err := jwtSvcA.GenerateAccessToken(uuid.New(), uuid.New(), "u@example.com", "U", nil, nil, nil)
	if err != nil {
		t.Fatalf("erro ao gerar token: %v", err)
	}

	if _, err := jwtSvcB.ValidateToken(token); err != ErrInvalidToken {
		t.Fatalf("esperava ErrInvalidToken para chave desconhecida, obteve %v", err)
	}
}

func TestJWTService_AlgoritmoHS256Rejeitado(t *testing.T) {
	jwtSvc, _ := newTestJWTService(t)

	// Token assinado com HMAC (ataque de confusão de algoritmo)
	hsToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "x"}).SignedString([]byte("qualquer"))
	if err != nil {
		t.Fatalf("erro ao gerar token HS256: %v", err)
	}

	if _, err := jwtSvc.ValidateToken(hsToken); err != ErrInvalidToken {
		t.Fatalf("esperava ErrInvalidToken para HS256, obteve %v", err)
	}
}

func TestJWTService_GetJWKSExpoeChaveAtual(t *testing.T) {
	jwtSvc, rsaSvc := newTestJWTService(t)

	jwks, err := jwtSvc.GetJWKS()
	if err != nil {
		t.Fatalf("erro ao obter JWKS: %v", err)
	}

	keys, ok := jwks["keys"].([]map[string]interface{})
	if !ok || len(keys) != 1 {
		t.Fatalf("esperava 1 chave no JWKS, obteve %v", jwks["keys"])
	}
	if keys[0]["kid"] != rsaSvc.GetCurrentKeyID() || keys[0]["alg"] != "RS256" || keys[0]["kty"] != "RSA" {
		t.Errorf("JWK inesperado: %v", keys[0])
	}
}
