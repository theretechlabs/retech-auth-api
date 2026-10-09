package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/theretech/retech-auth-api/internal/domain/entity"
	"github.com/theretech/retech-auth-api/internal/domain/repository"
)

// ErrRefreshTokenNotFound indica jti desconhecido.
var ErrRefreshTokenNotFound = errors.New("refresh token não encontrado")

type postgresRefreshTokenRepository struct {
	db *sql.DB
}

// NewPostgresRefreshTokenRepository cria uma nova instância de RefreshTokenRepository
func NewPostgresRefreshTokenRepository(db *sql.DB) repository.RefreshTokenRepository {
	return &postgresRefreshTokenRepository{db: db}
}

func (r *postgresRefreshTokenRepository) Create(ctx context.Context, t *entity.RefreshToken) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO refresh_tokens (id, user_id, application_id, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5)`,
		t.ID, t.UserID, t.ApplicationID, t.ExpiresAt, t.CreatedAt,
	)
	return err
}

func (r *postgresRefreshTokenRepository) FindByID(ctx context.Context, id uuid.UUID) (*entity.RefreshToken, error) {
	t := &entity.RefreshToken{}
	var reason sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT id, user_id, application_id, expires_at, created_at, revoked_at, revoked_reason, replaced_by
		FROM refresh_tokens WHERE id = $1`, id,
	).Scan(&t.ID, &t.UserID, &t.ApplicationID, &t.ExpiresAt, &t.CreatedAt, &t.RevokedAt, &reason, &t.ReplacedBy)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRefreshTokenNotFound
		}
		return nil, err
	}
	t.RevokedReason = reason.String
	return t, nil
}

func (r *postgresRefreshTokenRepository) Rotate(ctx context.Context, id, replacedBy uuid.UUID) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = NOW(), revoked_reason = $3, replaced_by = $2
		WHERE id = $1 AND revoked_at IS NULL`,
		id, replacedBy, entity.RevokeReasonRotated,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (r *postgresRefreshTokenRepository) Revoke(ctx context.Context, id uuid.UUID, reason string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE refresh_tokens SET revoked_at = NOW(), revoked_reason = $2
		WHERE id = $1 AND revoked_at IS NULL`, id, reason)
	return err
}

func (r *postgresRefreshTokenRepository) RevokeAllForUser(ctx context.Context, userID, applicationID uuid.UUID, reason string) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE refresh_tokens SET revoked_at = NOW(), revoked_reason = $3
		WHERE user_id = $1 AND application_id = $2 AND revoked_at IS NULL`, userID, applicationID, reason)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (r *postgresRefreshTokenRepository) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE expires_at < $1`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
