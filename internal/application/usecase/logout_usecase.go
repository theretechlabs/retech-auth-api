package usecase

import (
	"context"
	"errors"
	"log"

	"github.com/google/uuid"
	"github.com/theretech/retech-auth-api/internal/application/service"
	"github.com/theretech/retech-auth-api/internal/domain/entity"
	"github.com/theretech/retech-auth-api/internal/domain/repository"
)

// LogoutUseCase revoga refresh tokens. Access tokens continuam válidos até o
// `exp` (curto, JWT_EXPIRATION_MINUTES) — por isso os gateways de sessão
// chamam logout e descartam o access token localmente.
type LogoutUseCase struct {
	refreshRepo repository.RefreshTokenRepository
	jwtService  service.JWTService
}

// NewLogoutUseCase cria uma nova instância de LogoutUseCase
func NewLogoutUseCase(refreshRepo repository.RefreshTokenRepository, jwtService service.JWTService) *LogoutUseCase {
	return &LogoutUseCase{refreshRepo: refreshRepo, jwtService: jwtService}
}

// Execute revoga o refresh token apresentado. Com all=true revoga todos os
// refresh tokens do usuário na aplicação (logout de todos os dispositivos).
// Token já expirado é idempotente (nada a revogar).
func (uc *LogoutUseCase) Execute(ctx context.Context, refreshToken string, all bool) error {
	claims, err := uc.jwtService.ValidateRefreshToken(refreshToken)
	if err != nil {
		if errors.Is(err, service.ErrExpiredToken) {
			return nil
		}
		return ErrInvalidRefreshToken
	}
	jti, err := uuid.Parse(claims.ID)
	if err != nil {
		return ErrInvalidRefreshToken
	}
	if all {
		n, err := uc.refreshRepo.RevokeAllForUser(ctx, claims.UserID, claims.ApplicationID, entity.RevokeReasonLogoutAll)
		if err != nil {
			return err
		}
		log.Printf("[logout] todos os dispositivos user_id=%s app_id=%s revogados=%d", claims.UserID, claims.ApplicationID, n)
		return nil
	}
	return uc.refreshRepo.Revoke(ctx, jti, entity.RevokeReasonLogout)
}
