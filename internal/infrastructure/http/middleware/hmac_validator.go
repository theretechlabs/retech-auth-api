package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"
)

// Janela de aceitação do timestamp (anti-replay grosseiro). O nonce cobre o
// replay dentro da janela.
const (
	hmacMaxAge = 5 * time.Minute
	hmacSkew   = time.Minute
)

// ValidateHMAC valida a assinatura HMAC do body (sem nonce; compatibilidade).
func ValidateHMAC(body []byte, timestamp int64, signature, secret string) error {
	return ValidateHMACWithNonce(body, timestamp, "", signature, secret)
}

// ValidateHMACWithNonce valida HMAC-SHA256(body || timestamp || nonce). Nonce
// vazio reproduz o esquema antigo (body || timestamp). A unicidade do nonce é
// responsabilidade de quem chama (NonceStore).
func ValidateHMACWithNonce(body []byte, timestamp int64, nonce, signature, secret string) error {
	if secret == "" {
		return fmt.Errorf("secret não configurado")
	}

	// Validar timestamp (evitar replay attacks)
	now := time.Now().Unix()
	if timestamp < now-int64(hmacMaxAge.Seconds()) || timestamp > now+int64(hmacSkew.Seconds()) {
		return fmt.Errorf("timestamp inválido ou muito antigo")
	}

	expectedSignature := CalculateHMACWithNonce(body, timestamp, nonce, secret)

	// Comparar assinaturas de forma segura (constant-time)
	if !hmac.Equal([]byte(expectedSignature), []byte(signature)) {
		return fmt.Errorf("assinatura HMAC inválida")
	}

	return nil
}

// CalculateHMAC calcula a assinatura HMAC sem nonce (usado no CLI e em clientes legados)
func CalculateHMAC(body []byte, timestamp int64, secret string) string {
	return CalculateHMACWithNonce(body, timestamp, "", secret)
}

// CalculateHMACWithNonce calcula HMAC-SHA256(body || timestamp || nonce) em hex.
func CalculateHMACWithNonce(body []byte, timestamp int64, nonce, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	mac.Write([]byte(fmt.Sprintf("%d", timestamp)))
	if nonce != "" {
		mac.Write([]byte(nonce))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// ReadBody lê o body sem consumir (para usar no middleware)
func ReadBody(reader io.ReadCloser) ([]byte, error) {
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return body, nil
}
