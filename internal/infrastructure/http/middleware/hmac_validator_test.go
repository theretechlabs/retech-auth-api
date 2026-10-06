package middleware

import (
	"strings"
	"testing"
	"time"
)

const testSecret = "segredo-de-teste-nao-usar-em-producao"

func TestValidateHMAC_AssinaturaValidaAceita(t *testing.T) {
	body := []byte(`{"code":"app","name":"App"}`)
	ts := time.Now().Unix()

	sig := CalculateHMAC(body, ts, testSecret)

	if err := ValidateHMAC(body, ts, sig, testSecret); err != nil {
		t.Fatalf("esperava assinatura válida, obteve erro: %v", err)
	}
}

func TestValidateHMAC_BodyAdulteradoRejeitado(t *testing.T) {
	body := []byte(`{"code":"app","name":"App"}`)
	ts := time.Now().Unix()
	sig := CalculateHMAC(body, ts, testSecret)

	tampered := []byte(`{"code":"app","name":"Outro"}`)

	err := ValidateHMAC(tampered, ts, sig, testSecret)
	if err == nil {
		t.Fatal("esperava erro para body adulterado, obteve nil")
	}
	if !strings.Contains(err.Error(), "assinatura HMAC inválida") {
		t.Fatalf("mensagem inesperada: %v", err)
	}
}

func TestValidateHMAC_SecretDiferenteRejeitado(t *testing.T) {
	body := []byte(`{}`)
	ts := time.Now().Unix()
	sig := CalculateHMAC(body, ts, "outro-secret")

	if err := ValidateHMAC(body, ts, sig, testSecret); err == nil {
		t.Fatal("esperava erro para secret diferente, obteve nil")
	}
}

func TestValidateHMAC_TimestampForaDaJanelaRejeitado(t *testing.T) {
	body := []byte(`{}`)

	cases := []struct {
		nome string
		ts   int64
	}{
		{"muito antigo (10 min)", time.Now().Add(-10 * time.Minute).Unix()},
		{"no futuro (5 min)", time.Now().Add(5 * time.Minute).Unix()},
	}

	for _, tc := range cases {
		t.Run(tc.nome, func(t *testing.T) {
			sig := CalculateHMAC(body, tc.ts, testSecret)
			err := ValidateHMAC(body, tc.ts, sig, testSecret)
			if err == nil {
				t.Fatal("esperava erro de timestamp, obteve nil")
			}
			if !strings.Contains(err.Error(), "timestamp") {
				t.Fatalf("mensagem inesperada: %v", err)
			}
		})
	}
}

func TestValidateHMAC_SecretVazioRejeitado(t *testing.T) {
	body := []byte(`{}`)
	ts := time.Now().Unix()
	sig := CalculateHMAC(body, ts, "")

	if err := ValidateHMAC(body, ts, sig, ""); err == nil {
		t.Fatal("esperava erro para secret vazio, obteve nil")
	}
}
