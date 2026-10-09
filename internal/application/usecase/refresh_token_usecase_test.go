package usecase

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/theretech/retech-auth-api/internal/application/service"
	"github.com/theretech/retech-auth-api/internal/domain/dto"
	"github.com/theretech/retech-auth-api/internal/domain/entity"
	"github.com/theretech/retech-auth-api/internal/domain/repository"
)

// ---- fakes mínimos (embedding da interface: só o que o use case chama é implementado)

type fakeUserRepo struct {
	repository.UserRepository
	users map[uuid.UUID]*entity.User
}

func (f *fakeUserRepo) FindByID(_ context.Context, id uuid.UUID) (*entity.User, error) {
	if u, ok := f.users[id]; ok {
		return u, nil
	}
	return nil, errors.New("não encontrado")
}

type fakeAuthRepo struct{ repository.AuthRepository }

func (fakeAuthRepo) FindUserApplication(context.Context, uuid.UUID, uuid.UUID) (*entity.UserApplication, error) {
	return nil, errors.New("sem vínculo")
}
func (fakeAuthRepo) GetUserRoles(context.Context, uuid.UUID, uuid.UUID) ([]*entity.Role, error) {
	return []*entity.Role{{Code: "viewer"}}, nil
}
func (fakeAuthRepo) GetUserPermissions(context.Context, uuid.UUID, uuid.UUID) ([]*repository.PermissionInfo, error) {
	return nil, nil
}

type fakeRefreshRepo struct {
	tokens  map[uuid.UUID]*entity.RefreshToken
	revoked []string
}

func newFakeRefreshRepo() *fakeRefreshRepo {
	return &fakeRefreshRepo{tokens: map[uuid.UUID]*entity.RefreshToken{}}
}
func (f *fakeRefreshRepo) Create(_ context.Context, t *entity.RefreshToken) error {
	cp := *t
	f.tokens[t.ID] = &cp
	return nil
}
func (f *fakeRefreshRepo) FindByID(_ context.Context, id uuid.UUID) (*entity.RefreshToken, error) {
	if t, ok := f.tokens[id]; ok {
		cp := *t
		return &cp, nil
	}
	return nil, errors.New("não encontrado")
}
func (f *fakeRefreshRepo) Rotate(_ context.Context, id, replacedBy uuid.UUID) (bool, error) {
	t, ok := f.tokens[id]
	if !ok || t.RevokedAt != nil {
		return false, nil
	}
	now := time.Now()
	t.RevokedAt, t.RevokedReason, t.ReplacedBy = &now, entity.RevokeReasonRotated, &replacedBy
	return true, nil
}
func (f *fakeRefreshRepo) Revoke(_ context.Context, id uuid.UUID, reason string) error {
	if t, ok := f.tokens[id]; ok && t.RevokedAt == nil {
		now := time.Now()
		t.RevokedAt, t.RevokedReason = &now, reason
	}
	return nil
}
func (f *fakeRefreshRepo) RevokeAllForUser(_ context.Context, userID, appID uuid.UUID, reason string) (int64, error) {
	var n int64
	for _, t := range f.tokens {
		if t.UserID == userID && t.ApplicationID == appID && t.RevokedAt == nil {
			now := time.Now()
			t.RevokedAt, t.RevokedReason = &now, reason
			n++
		}
	}
	f.revoked = append(f.revoked, reason)
	return n, nil
}
func (f *fakeRefreshRepo) DeleteExpired(context.Context, time.Time) (int64, error) { return 0, nil }

func newJWT(t *testing.T) service.JWTService {
	t.Helper()
	rsaSvc, err := service.NewRSAKeyService(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatal(err)
	}
	return service.NewJWTService(rsaSvc, 15*time.Minute, time.Hour, "")
}

func issue(t *testing.T, jwtSvc service.JWTService, repo *fakeRefreshRepo, userID, appID uuid.UUID) service.IssuedToken {
	t.Helper()
	tok, err := jwtSvc.GenerateRefreshToken(service.TokenSubject{UserID: userID, ApplicationID: appID, ApplicationCode: "app", Email: "u@x", Name: "U"})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(context.Background(), &entity.RefreshToken{ID: tok.JTI, UserID: userID, ApplicationID: appID, ExpiresAt: tok.ExpiresAt, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestRefresh_RotacionaEInvalidaOAnterior(t *testing.T) {
	jwtSvc := newJWT(t)
	userID, appID := uuid.New(), uuid.New()
	users := &fakeUserRepo{users: map[uuid.UUID]*entity.User{userID: {ID: userID, Email: "u@x", Name: "U", Active: true}}}
	repo := newFakeRefreshRepo()
	uc := NewRefreshTokenUseCase(users, fakeAuthRepo{}, repo, jwtSvc)

	first := issue(t, jwtSvc, repo, userID, appID)

	resp, err := uc.Execute(context.Background(), dto.RefreshTokenRequest{RefreshToken: first.Token})
	if err != nil {
		t.Fatalf("refresh deveria passar: %v", err)
	}
	if resp.RefreshToken == first.Token {
		t.Fatal("refresh token deveria ser rotacionado")
	}
	access, err := jwtSvc.ValidateAccessToken(resp.AccessToken)
	if err != nil || access.Audience[0] != "app" || access.Roles[0] != "viewer" {
		t.Fatalf("access token inesperado: %v %+v", err, access)
	}
	if old := repo.tokens[first.JTI]; old.RevokedAt == nil || old.RevokedReason != entity.RevokeReasonRotated || old.ReplacedBy == nil {
		t.Fatalf("jti antigo deveria estar rotacionado: %+v", old)
	}

	// Segundo refresh com o novo token: ok.
	if _, err := uc.Execute(context.Background(), dto.RefreshTokenRequest{RefreshToken: resp.RefreshToken}); err != nil {
		t.Fatalf("refresh com o token novo deveria passar: %v", err)
	}
}

func TestRefresh_ReusoRevogaFamiliaInteira(t *testing.T) {
	jwtSvc := newJWT(t)
	userID, appID := uuid.New(), uuid.New()
	users := &fakeUserRepo{users: map[uuid.UUID]*entity.User{userID: {ID: userID, Email: "u@x", Name: "U", Active: true}}}
	repo := newFakeRefreshRepo()
	uc := NewRefreshTokenUseCase(users, fakeAuthRepo{}, repo, jwtSvc)

	first := issue(t, jwtSvc, repo, userID, appID)
	resp, err := uc.Execute(context.Background(), dto.RefreshTokenRequest{RefreshToken: first.Token})
	if err != nil {
		t.Fatal(err)
	}

	// Atacante reapresenta o token já rotacionado.
	if _, err := uc.Execute(context.Background(), dto.RefreshTokenRequest{RefreshToken: first.Token}); err != ErrInvalidRefreshToken {
		t.Fatalf("reuso deveria falhar com ErrInvalidRefreshToken, obteve %v", err)
	}
	// ...e o token legítimo (o novo) também morre.
	if _, err := uc.Execute(context.Background(), dto.RefreshTokenRequest{RefreshToken: resp.RefreshToken}); err != ErrInvalidRefreshToken {
		t.Fatalf("família deveria estar revogada, obteve %v", err)
	}
	if len(repo.revoked) == 0 || repo.revoked[0] != entity.RevokeReasonReuse {
		t.Fatalf("esperava revogação por reuso, obteve %v", repo.revoked)
	}
}

func TestRefresh_TokenDesconhecidoOuUsuarioInativo(t *testing.T) {
	jwtSvc := newJWT(t)
	userID, appID := uuid.New(), uuid.New()
	users := &fakeUserRepo{users: map[uuid.UUID]*entity.User{userID: {ID: userID, Email: "u@x", Active: false}}}
	repo := newFakeRefreshRepo()
	uc := NewRefreshTokenUseCase(users, fakeAuthRepo{}, repo, jwtSvc)

	// jti nunca persistido (ex.: emitido antes da migração): inválido.
	unknown, _ := jwtSvc.GenerateRefreshToken(service.TokenSubject{UserID: userID, ApplicationID: appID})
	if _, err := uc.Execute(context.Background(), dto.RefreshTokenRequest{RefreshToken: unknown.Token}); err != ErrInvalidRefreshToken {
		t.Fatalf("esperava ErrInvalidRefreshToken, obteve %v", err)
	}

	// access token no lugar do refresh: inválido.
	access, _ := jwtSvc.GenerateAccessToken(service.TokenSubject{UserID: userID, ApplicationID: appID})
	if _, err := uc.Execute(context.Background(), dto.RefreshTokenRequest{RefreshToken: access}); err != ErrInvalidRefreshToken {
		t.Fatalf("esperava ErrInvalidRefreshToken para access token, obteve %v", err)
	}

	// usuário inativo
	tok := issue(t, jwtSvc, repo, userID, appID)
	if _, err := uc.Execute(context.Background(), dto.RefreshTokenRequest{RefreshToken: tok.Token}); err != ErrInactiveUser {
		t.Fatalf("esperava ErrInactiveUser, obteve %v", err)
	}
}

func TestLogout_RevogaEImpedeRefresh(t *testing.T) {
	jwtSvc := newJWT(t)
	userID, appID := uuid.New(), uuid.New()
	users := &fakeUserRepo{users: map[uuid.UUID]*entity.User{userID: {ID: userID, Email: "u@x", Active: true}}}
	repo := newFakeRefreshRepo()
	refresh := NewRefreshTokenUseCase(users, fakeAuthRepo{}, repo, jwtSvc)
	logout := NewLogoutUseCase(repo, jwtSvc)

	a := issue(t, jwtSvc, repo, userID, appID)
	b := issue(t, jwtSvc, repo, userID, appID)

	if err := logout.Execute(context.Background(), a.Token, false); err != nil {
		t.Fatal(err)
	}
	if repo.tokens[a.JTI].RevokedReason != entity.RevokeReasonLogout {
		t.Fatalf("esperava logout, obteve %q", repo.tokens[a.JTI].RevokedReason)
	}
	if repo.tokens[b.JTI].RevokedAt != nil {
		t.Fatal("logout simples não deveria afetar outro dispositivo")
	}

	if err := logout.Execute(context.Background(), b.Token, true); err != nil {
		t.Fatal(err)
	}
	if repo.tokens[b.JTI].RevokedReason != entity.RevokeReasonLogoutAll {
		t.Fatalf("esperava logout_all, obteve %q", repo.tokens[b.JTI].RevokedReason)
	}
	if _, err := refresh.Execute(context.Background(), dto.RefreshTokenRequest{RefreshToken: b.Token}); err != ErrInvalidRefreshToken {
		t.Fatalf("refresh após logout deveria falhar, obteve %v", err)
	}

	if err := logout.Execute(context.Background(), "lixo", false); err != ErrInvalidRefreshToken {
		t.Fatalf("token inválido: esperava ErrInvalidRefreshToken, obteve %v", err)
	}
}
