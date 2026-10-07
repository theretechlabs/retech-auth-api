# Chaves de assinatura JWT — como é hoje e roadmap

Registro de 2026-10-07. Complementa o backlog de hardening em [`SECURITY.md`](../SECURITY.md).

## 1. Como funciona hoje

### O que é a chave

O auth assina access e refresh tokens com **RS256**: um par RSA 2048. A chave **privada** só existe
no auth. As APIs consumidoras (meufin-api, cashflowfy-api) baixam a chave **pública** em runtime por
`GET /.well-known/jwks.json` (`AUTH_JWKS_URL`) e validam a assinatura localmente. Nenhuma env das
APIs contém essa chave.

Não confundir com:

| Segredo | Onde vive | Para quê |
|---|---|---|
| Chave RSA privada | arquivo `.pem` no volume do auth | assinar JWTs |
| `BOOTSTRAP_SECRET` / `AUTH_BOOTSTRAP_SECRET` | env do auth e das APIs (mesmo valor) | HMAC do `/applications/sync` e `/password-reset/*` |
| `SESSION_ENCRYPTION_KEY` | env de cada API consumidora (valor próprio) | cifrar o JWT guardado na sessão daquela API |

### Ciclo de vida (`internal/application/service/rsa_key_service.go`)

1. No boot, `NewRSAKeyService(JWT_RSA_KEYS_DIR)` lista `*.pem` no diretório e carrega todas.
2. `kid` = 8 bytes de SHA3-256 da chave pública, base64url (nome do arquivo = `<kid>.pem`).
3. **Chave atual** = o `kid` lexicograficamente maior entre os carregados.
4. Sem nenhum `.pem`, gera um par novo e salva.
5. `GET /.well-known/jwks.json` publica **todas** as chaves carregadas; tokens antigos continuam
   validando enquanto o `.pem` existir no diretório.
6. `RotateKey()` existe no serviço mas **não há rota nem comando** que o chame.

### Deploy (Railway, `retech-core-services` → `retech-auth-api`)

- Volume montado em `/app/keys`, `JWT_RSA_KEYS_DIR=/app/keys`.
- O volume monta como root e o container roda como usuário `app` (Dockerfile), por isso
  `RAILWAY_RUN_UID=0`: o processo roda como root.
- Antes do volume (até 2026-10-07) a chave era regenerada a cada deploy e **todos os usuários eram
  deslogados** (access e refresh assinados pela chave anterior deixavam de validar).

### Limitações conhecidas

| # | Problema | Impacto |
|---|---|---|
| A | Processo roda como root (`RAILWAY_RUN_UID=0`) | perde o hardening de usuário não-root do Dockerfile |
| B | "Chave atual" por ordem lexicográfica de um hash aleatório | após uma rotação + restart, a chave antiga pode voltar a ser a atual se o `kid` dela for "maior" |
| C | Sem rotação operacional | mesma chave indefinidamente; comprometimento exige troca manual e desloga todos |
| D | Sem backup do volume | perder o volume = chave nova = todos deslogados (sem outro dano) |
| E | Sem `iss`/`aud`/`typ`/`jti` nos tokens (SECURITY.md itens 1 e 2) | qualquer token RS256 da mesma chave é aceito por qualquer consumidor |

## 2. Roadmap

Ordem sugerida. Cada item é uma PR pequena e independente.

### Curto prazo

1. **Voltar a rodar como `app`.** Entrypoint faz `chown -R app:app /app/keys` como root e troca de
   usuário (`su-exec`/`gosu`) antes de subir o binário. Remove `RAILWAY_RUN_UID=0`. Resolve A.
2. **Chave atual por data, não por hash.** Guardar `created_at` (mtime do arquivo ou
   `<timestamp>-<kid>.pem`) e escolher a mais recente. Resolve B. Pré-requisito do item 3.
3. **Rotação operacional.** Comando `cmd/tools/rotate-key` (ou rota admin protegida por HMAC) que:
   gera nova chave, passa a assinar com ela, mantém as anteriores só para validação; job que apaga
   `.pem` com mais de `JWT_REFRESH_EXPIRATION_HOURS` + margem. JWKS publica as duas durante a
   transição. Resolve C. Consumidores já recarregam o JWKS por `kid` desconhecido.
4. **Backup.** Script `make keys-backup` que exporta o volume (`railway volume` ou `railway ssh`)
   cifrado com `age`/`gpg` para o cofre da empresa. Documentar restore. Mitiga D.

### Médio prazo

5. **Claims `iss`, `aud`, `typ`, `jti`** (SECURITY.md 1 e 2). `aud` = `application_code`; cada API
   consumidora valida o seu. Refresh com `typ: refresh` deixa de servir como access.
6. **Revogação** (SECURITY.md 3): `user.version` checado no refresh; `jti` em denylist curta para
   access tokens comprometidos.
7. **Chave vinda de secret manager em vez de arquivo.** Variável `JWT_PRIVATE_KEYS` (JSON com
   `{kid, created_at, pem}`) injetada pelo Railway/Vault. Infra fica stateless, volume some, rotação
   vira "atualizar a env". Só vale a pena depois do item 3 (precisa do formato multi-chave).

### Longo prazo (só se o auth virar produto com clientes externos)

8. **Assinatura via KMS/HSM** (AWS KMS, GCP KMS, Vault Transit). A chave privada nunca sai do
   hardware; o auth chama `Sign`. Custo e latência por token; hoje desproporcional para duas apps
   internas.
9. **Alternar para EdDSA (Ed25519)**: chaves menores, assinatura mais rápida, JWKS `OKP`. Exige
   suporte nos consumidores (jwt/v5 suporta).

## 3. O que NÃO fazer

- Colocar a chave privada em env "por simplicidade" sem o formato multi-chave do item 7: mesma
  exposição que o arquivo, e perde a capacidade de manter duas chaves ativas na rotação.
- Rotacionar apagando o `.pem` antigo no mesmo deploy: invalida todos os refresh tokens de uma vez.
  A chave antiga precisa continuar no JWKS até o último refresh emitido com ela expirar (168h).
