package middleware

import (
	"sync"
	"time"
)

// NonceStore lembra nonces já aceitos durante a janela do HMAC (anti-replay).
// Em memória, por instância: com réplicas, cada uma recusa só o que ela viu.
type NonceStore struct {
	ttl time.Duration
	now func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time
}

// maxNonces força varredura quando o mapa cresce.
const maxNonces = 50000

// NewNonceStore cria o store com a janela informada (>= janela do timestamp).
func NewNonceStore(ttl time.Duration) *NonceStore {
	return &NonceStore{ttl: ttl, now: time.Now, seen: make(map[string]time.Time)}
}

// Remember registra o nonce. Retorna false se já tinha sido visto (replay).
func (s *NonceStore) Remember(nonce string) bool {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if exp, ok := s.seen[nonce]; ok && now.Before(exp) {
		return false
	}
	if len(s.seen) >= maxNonces {
		for k, exp := range s.seen {
			if !now.Before(exp) {
				delete(s.seen, k)
			}
		}
	}
	s.seen[nonce] = now.Add(s.ttl)
	return true
}
