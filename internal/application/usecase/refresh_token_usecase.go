package usecase

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/theretech/retech-auth-api/internal/application/service"
	"github.com/theretech/retech-auth-api/internal/domain/dto"
	"github.com/theretech/retech-auth-api/internal/domain/entity"
	"github.com/theretech/retech-auth-api/internal/domain/repository"
)

var (
	ErrInvalidRefreshToken = errors.New("refresh token inválido")
)

// RefreshTokenUseCase renova o par de tokens com rotação do refresh token:
// cada refresh token vale uma única renovação. Reapresentar um jti já
// rotacionado (reuso) revoga todos os refresh tokens do usuário na aplicação.
type RefreshTokenUseCase struct {
	userRepo    repository.UserRepository
	authRepo    repository.AuthRepository
	refreshRepo repository.RefreshTokenRepository
	jwtService  service.JWTService
	now         func() time.Time
}

// NewRefreshTokenUseCase cria uma nova instância de RefreshTokenUseCase
func NewRefreshTokenUseCase(
	userRepo repository.UserRepository,
	authRepo repository.AuthRepository,
	refreshRepo repository.RefreshTokenRepository,
	jwtService service.JWTService,
) *RefreshTokenUseCase {
	return &RefreshTokenUseCase{
		userRepo:    userRepo,
		authRepo:    authRepo,
		refreshRepo: refreshRepo,
		jwtService:  jwtService,
		now:         time.Now,
	}
}

// Execute executa a renovação do token
func (uc *RefreshTokenUseCase) Execute(ctx context.Context, req dto.RefreshTokenRequest) (*dto.AuthenticateResponse, error) {
	// Valida assinatura, iss, exp e tipo (typ=refresh com jti).
	claims, err := uc.jwtService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, ErrInvalidRefreshToken
	}
	jti, err := uuid.Parse(claims.ID)
	if err != nil {
		return nil, ErrInvalidRefreshToken
	}

	stored, err := uc.refreshRepo.FindByID(ctx, jti)
	if err != nil {
		return nil, ErrInvalidRefreshToken
	}
	if stored.RevokedAt != nil {
		// Reuso: o portador deste token já o trocou (ou fez logout). Alguém
		// tem uma cópia — derruba a família inteira.
		n, _ := uc.refreshRepo.RevokeAllForUser(ctx, stored.UserID, stored.ApplicationID, entity.RevokeReasonReuse)
		log.Printf("[refresh] reuso de refresh token jti=%s user_id=%s app_id=%s motivo_anterior=%q revogados=%d", jti, stored.UserID, stored.ApplicationID, stored.RevokedReason, n)
		return nil, ErrInvalidRefreshToken
	}
	if !stored.Usable(uc.now()) {
		return nil, ErrInvalidRefreshToken
	}

	// Busca o usuário para verificar se ainda está ativo
	user, err := uc.userRepo.FindByID(ctx, stored.UserID)
	if err != nil {
		return nil, ErrInvalidRefreshToken
	}

	if !user.Active {
		return nil, ErrInactiveUser
	}

	// Busca tenant_id atual do user_application (reflete mudanças sem precisar relogar)
	// Fallback para claims se não encontrar o vínculo
	tenantID := claims.TenantID
	if userApp, err := uc.authRepo.FindUserApplication(ctx, user.ID, stored.ApplicationID); err == nil {
		tenantID = userApp.TenantID
	}

	// Busca as roles do usuário para incluir no novo token
	// Se falhar, usa roles do token antigo (fallback para compatibilidade)
	var roleCodes []string
	roles, err := uc.authRepo.GetUserRoles(ctx, user.ID, stored.ApplicationID)
	if err == nil && len(roles) > 0 {
		roleCodes = make([]string, 0, len(roles))
		for _, role := range roles {
			if role.Code != "" {
				roleCodes = append(roleCodes, role.Code)
			}
		}
	} else {
		roleCodes = claims.Roles
	}

	// Permissions efetivas recalculadas a cada refresh — é assim que mudança de
	// grupo/permissão se propaga sem relogin. Fallback: perms do token antigo.
	var permCodes []string
	if permissions, permErr := uc.authRepo.GetUserPermissions(ctx, user.ID, stored.ApplicationID); permErr == nil {
		permCodes = buildPermCodes(roleCodes, permissions)
	} else {
		permCodes = claims.Perms
	}

	subject := service.TokenSubject{
		UserID: user.ID, ApplicationID: stored.ApplicationID, ApplicationCode: audience(claims),
		Email: user.Email, Name: user.Name, TenantID: tenantID, Roles: roleCodes, Perms: permCodes,
	}

	newRefresh, err := uc.jwtService.GenerateRefreshToken(subject)
	if err != nil {
		return nil, err
	}
	// Rotação atômica: só quem consegue revogar o jti antigo emite o novo.
	rotated, err := uc.refreshRepo.Rotate(ctx, jti, newRefresh.JTI)
	if err != nil {
		return nil, err
	}
	if !rotated {
		n, _ := uc.refreshRepo.RevokeAllForUser(ctx, stored.UserID, stored.ApplicationID, entity.RevokeReasonReuse)
		log.Printf("[refresh] corrida/reuso na rotação jti=%s user_id=%s revogados=%d", jti, stored.UserID, n)
		return nil, ErrInvalidRefreshToken
	}
	if err := uc.refreshRepo.Create(ctx, &entity.RefreshToken{
		ID: newRefresh.JTI, UserID: user.ID, ApplicationID: stored.ApplicationID,
		ExpiresAt: newRefresh.ExpiresAt, CreatedAt: uc.now(),
	}); err != nil {
		return nil, err
	}

	accessToken, err := uc.jwtService.GenerateAccessToken(subject)
	if err != nil {
		return nil, err
	}

	return &dto.AuthenticateResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefresh.Token,
		TokenType:    "Bearer",
		ExpiresIn:    uc.jwtService.GetExpirationTime(),
		User: dto.UserDTO{
			ID:    user.ID,
			Email: user.Email,
			Name:  user.Name,
		},
	}, nil
}

// audience devolve o application_code carregado no `aud` do token (ou vazio).
func audience(claims *service.Claims) string {
	if len(claims.Audience) > 0 {
		return claims.Audience[0]
	}
	return ""
}
