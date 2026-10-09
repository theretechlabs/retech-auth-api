package entity

import (
	"time"

	"github.com/google/uuid"
)

// RefreshToken é o registro de um refresh token emitido (ID = claim `jti`).
// Só o jti é persistido — o token em si nunca vai ao banco. Permite rotação
// (um refresh token vale uma única renovação), revogação (logout) e detecção
// de reuso (um jti já rotacionado apresentado de novo = família comprometida).
type RefreshToken struct {
	ID            uuid.UUID  `json:"id"`
	UserID        uuid.UUID  `json:"user_id"`
	ApplicationID uuid.UUID  `json:"application_id"`
	ExpiresAt     time.Time  `json:"expires_at"`
	CreatedAt     time.Time  `json:"created_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokedReason string     `json:"revoked_reason,omitempty"`
	ReplacedBy    *uuid.UUID `json:"replaced_by,omitempty"`
}

// Motivos de revogação.
const (
	RevokeReasonRotated   = "rotated"
	RevokeReasonLogout    = "logout"
	RevokeReasonLogoutAll = "logout_all"
	RevokeReasonReuse     = "reuse"
)

// Usable informa se o token ainda pode ser rotacionado.
func (t *RefreshToken) Usable(now time.Time) bool {
	return t.RevokedAt == nil && now.Before(t.ExpiresAt)
}
