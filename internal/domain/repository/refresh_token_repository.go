package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/theretech/retech-auth-api/internal/domain/entity"
)

// RefreshTokenRepository persiste os jti dos refresh tokens emitidos.
type RefreshTokenRepository interface {
	Create(ctx context.Context, token *entity.RefreshToken) error
	FindByID(ctx context.Context, id uuid.UUID) (*entity.RefreshToken, error)
	// Rotate revoga `id` apontando para `replacedBy`. Retorna false se o token já
	// estava revogado (reuso ou corrida) — nesse caso nada é alterado.
	Rotate(ctx context.Context, id, replacedBy uuid.UUID) (bool, error)
	Revoke(ctx context.Context, id uuid.UUID, reason string) error
	// RevokeAllForUser revoga todos os refresh tokens ativos do usuário na aplicação.
	RevokeAllForUser(ctx context.Context, userID, applicationID uuid.UUID, reason string) (int64, error)
	// DeleteExpired apaga tokens expirados antes de `before` (manutenção).
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)
}
