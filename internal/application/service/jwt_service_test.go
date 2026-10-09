package service

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

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

	return NewJWTService(rsaSvc, time.Hour, 2*time.Hour, "test-issuer"), rsaSvc
}

func subject() TokenSubject {
	return TokenSubject{UserID: uuid.New(), ApplicationID: uuid.New(), ApplicationCode: "app", Email: "u@example.com", Name: "U"}
}

func TestJWTService_RoundTripAccessToken(t *testing.T) {
	jwtSvc, rsaSvc := newTestJWTService(t)

	userID := uuid.New()
	appID := uuid.New()
	tenant := "tenant-123"
	roles := []string{"master"}
	perms := []string{"all:manage"}

	token, err := jwtSvc.GenerateAccessToken(TokenSubject{
		UserID: userID, ApplicationID: appID, ApplicationCode: "retech-fin-admin",
		Email: "user@example.com", Name: "Usuário", TenantID: &tenant, Roles: roles, Perms: perms,
	})
	if err != nil {
		t.Fatalf("erro ao gerar access token: %v", err)
	}

	claims, err := jwtSvc.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("erro ao validar token: %v", err)
	}
	if claims.Typ != TokenTypeAccess || claims.Issuer != "test-issuer" || claims.ID == "" {
		t.Errorf("typ/iss/jti inesperados: typ=%q iss=%q jti=%q", claims.Typ, claims.Issuer, claims.ID)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "retech-fin-admin" {
		t.Errorf("aud inesperado: %v", claims.Audience)
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

	s := subject()
	s.Roles = []string{"viewer"}
	s.Perms = []string{"x:view"}
	issued, err := jwtSvc.GenerateRefreshToken(s)
	if err != nil {
		t.Fatalf("erro ao gerar refresh token: %v", err)
	}

	claims, err := jwtSvc.ValidateRefreshToken(issued.Token)
	if err != nil {
		t.Fatalf("erro ao validar refresh token: %v", err)
	}
	if len(claims.Perms) != 0 {
		t.Errorf("refresh token não deveria carregar perms, obteve %v", claims.Perms)
	}
	if claims.TenantID != nil {
		t.Errorf("tenant_id deveria ser nil, obteve %v", *claims.TenantID)
	}
	if claims.ID != issued.JTI.String() {
		t.Errorf("jti inesperado: %s vs %s", claims.ID, issued.JTI)
	}
	if !issued.ExpiresAt.Equal(claims.ExpiresAt.Time) {
		t.Errorf("exp inesperado: %v vs %v", issued.ExpiresAt, claims.ExpiresAt.Time)
	}
}

func TestJWTService_TiposNaoSaoIntercambiaveis(t *testing.T) {
	jwtSvc, _ := newTestJWTService(t)
	s := subject()

	access, err := jwtSvc.GenerateAccessToken(s)
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := jwtSvc.GenerateRefreshToken(s)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := jwtSvc.ValidateAccessToken(refresh.Token); err != ErrWrongTokenType {
		t.Fatalf("refresh como access: esperava ErrWrongTokenType, obteve %v", err)
	}
	if _, err := jwtSvc.ValidateRefreshToken(access); err != ErrWrongTokenType {
		t.Fatalf("access como refresh: esperava ErrWrongTokenType, obteve %v", err)
	}
}

func TestJWTService_IssuerDiferenteRejeitado(t *testing.T) {
	rsaSvc, err := NewRSAKeyService(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatal(err)
	}
	a := NewJWTService(rsaSvc, time.Hour, 2*time.Hour, "iss-a")
	b := NewJWTService(rsaSvc, time.Hour, 2*time.Hour, "iss-b")

	token, err := a.GenerateAccessToken(subject())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.ValidateToken(token); err != ErrInvalidToken {
		t.Fatalf("mesma chave, iss diferente: esperava ErrInvalidToken, obteve %v", err)
	}
}

func TestJWTService_TokenLegadoSemTypRejeitadoComoRefresh(t *testing.T) {
	jwtSvc, rsaSvc := newTestJWTService(t)
	kid := rsaSvc.GetCurrentKeyID()
	priv, _ := rsaSvc.GetPrivateKey(kid)

	legacy := jwt.NewWithClaims(jwt.SigningMethodRS256, &Claims{
		UserID: uuid.New(), RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "test-issuer", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)), IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	})
	legacy.Header["kid"] = kid
	signed, err := legacy.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jwtSvc.ValidateRefreshToken(signed); err != ErrWrongTokenType {
		t.Fatalf("esperava ErrWrongTokenType, obteve %v", err)
	}
	if _, err := jwtSvc.ValidateAccessToken(signed); err != ErrWrongTokenType {
		t.Fatalf("esperava ErrWrongTokenType, obteve %v", err)
	}
}

func TestJWTService_TokenAdulteradoRejeitado(t *testing.T) {
	jwtSvc, _ := newTestJWTService(t)

	token, err := jwtSvc.GenerateAccessToken(subject())
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

	token, err := jwtSvcA.GenerateAccessToken(subject())
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
