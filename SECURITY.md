# Segurança

## 1. Incidente: segredos versionados no histórico do git

Até a PR `chore(security)` que introduziu este arquivo, o repositório
versionava os seguintes artefatos sensíveis:

| Artefato | Conteúdo exposto |
| --- | --- |
| `.env` | `DB_PASSWORD`, `PGPASSWORD`, `BOOTSTRAP_SECRET` e demais variáveis reais |
| `mcp/postgres/.env` | `DATABASE_URL` com senha do banco |
| `keys/m4vNIvWOllU.pem` | **chave privada RSA** usada para assinar todos os JWTs (`kid` `m4vNIvWOllU`) |

Esses arquivos foram removidos do índice (`git rm --cached`), mas **continuam
recuperáveis em qualquer commit anterior**. Remover do tracking não é
rotacionar. Enquanto a rotação abaixo não for feita, assuma que qualquer pessoa
com acesso ao histórico (clones, forks, CI caches) consegue forjar tokens
válidos e acessar o banco.

### 1.1 Rotação obrigatória (fazer antes ou junto do merge)

1. **Chave RSA do JWT**
   - Em produção, gerar uma nova chave no volume apontado por
     `JWT_RSA_KEYS_DIR` com nome lexicograficamente maior que `m4vNIvWOllU`
     (ex.: `openssl genrsa -out "$JWT_RSA_KEYS_DIR/zz-$(date +%Y%m%d).pem" 2048`)
     ou simplesmente remover o `.pem` antigo e deixar a aplicação gerar outra.
   - Remover `m4vNIvWOllU.pem` do volume. Como não há revogação de tokens,
     todo access/refresh token emitido com a chave vazada deve passar a falhar
     na validação — isso só acontece quando o `.pem` antigo some do diretório.
   - Clientes que fazem cache do JWKS precisam recarregar as chaves.
2. **`BOOTSTRAP_SECRET`**: gerar novo valor (`openssl rand -base64 32`),
   atualizar no ambiente da API e em todos os clientes que chamam
   `/applications/sync` e `/password-reset/*` via HMAC.
3. **Senha do PostgreSQL**: `ALTER USER <usuario> WITH PASSWORD '<nova>'`,
   atualizar `DB_PASSWORD`/`PGPASSWORD`/`DATABASE_URL` em todos os ambientes
   e ferramentas (incluindo `mcp/postgres/.env` local).
4. Revisar logs de acesso ao banco e à API no período de exposição.

### 1.2 Purga do histórico (follow-up, NÃO executada nesta PR)

Reescrever histórico é destrutivo e exige coordenação com todos que têm clone.
Fazer em uma janela combinada, depois da rotação acima:

```bash
# 1. Instalar git-filter-repo (https://github.com/newren/git-filter-repo)
brew install git-filter-repo   # ou: pip install git-filter-repo

# 2. Clonar uma cópia fresca (filter-repo recusa rodar em clone "sujo")
git clone --mirror git@github.com:theretechlabs/retech-auth-api.git auth-api-purge.git
cd auth-api-purge.git

# 3. Remover os caminhos sensíveis de TODOS os commits
git filter-repo --invert-paths \
  --path .env \
  --path mcp/postgres/.env \
  --path keys/m4vNIvWOllU.pem \
  --path-glob 'keys/*.pem' \
  --path mcp/postgres/node_modules

# 4. Conferir que nada sobrou
git log --all --diff-filter=A --name-only --format= | grep -E '\.env$|\.pem$' || echo OK

# 5. Forçar push de todas as refs (branches e tags)
git push --force --mirror

# 6. No GitHub: Settings > General > "Danger Zone" não basta — abrir ticket no
#    suporte GitHub pedindo limpeza de objetos órfãos/caches de PR, e pedir que
#    todos os colaboradores apaguem clones antigos e clonem novamente.
```

## 2. Reportando vulnerabilidades

Não abra issue pública. Envie e-mail para **suporte@theretech.com.br** com
assunto `[SECURITY] retech-auth-api`, incluindo passos de reprodução, impacto
e versão/commit afetado. Respondemos em até 5 dias úteis e combinamos prazo de
divulgação coordenada. Se precisar de canal cifrado, solicite a chave PGP na
primeira mensagem.

## 3. Backlog de hardening conhecido

Itens identificados em revisão e **não corrigidos** nesta PR (que se limitou a
higiene de repositório e CI, sem alterar comportamento). Ordem aproximada de
prioridade.

| # | Item | Onde | Risco |
| --- | --- | --- | --- |
| 0 | **Dependências vulneráveis.** `govulncheck` acusa [GO-2025-3553](https://pkg.go.dev/vuln/GO-2025-3553) em `github.com/golang-jwt/jwt/v5@v5.2.0` (alocação excessiva de memória ao parsear header; fix em v5.2.2), alcançável a partir de `ValidateToken`. Além disso há 10 vulnerabilidades em pacotes importados e 22 em módulos requeridos (gin v1.9.1, x/net, x/crypto etc.) que o código não parece chamar. Abrir PR dedicada de `go get -u` + `go mod tidy` e, só então, remover o `continue-on-error` do job `govulncheck` em `.github/workflows/ci.yml`. | `go.mod`, `internal/application/service/jwt_service.go` | Alto |
| 1 | JWT sem claims `typ`, `iss`, `aud` e `jti`. Sem `iss`/`aud` qualquer token RS256 válido da mesma chave serve em qualquer consumidor; sem `jti` não há como revogar individualmente. | `internal/application/service/jwt_service.go` | Alto |
| 2 | Access token e refresh token são intercambiáveis: mesma struct `Claims`, mesma chave, nenhum marcador de tipo. Um refresh token (7 dias) é aceito pelo `AuthMiddleware` como access token, e vice-versa. | `jwt_service.go`, `internal/infrastructure/http/middleware/auth_middleware.go`, `internal/application/usecase/refresh_token_usecase.go` | Alto |
| 3 | Não existe logout nem revogação de tokens (nem por `jti`, nem por `user.version` no refresh). | `cmd/api/main.go`, `refresh_token_usecase.go` | Alto |
| 4 | O grupo `protected` só exige JWT válido; não há verificação de role/permission em `/applications`, `/roles`, `/permissions` nem em `POST /users/:id/password/reset`. Qualquer usuário autenticado de qualquer aplicação pode administrar RBAC e resetar senhas de outros. | `cmd/api/main.go` (grupo `protected`), handlers em `internal/infrastructure/http/handler/` | Crítico |
| 5 | `ListUsersUseCase` filtra apenas por `application_id`; não aplica `tenant_id` do token. Usuários de um tenant enxergam todos os usuários da aplicação. | `internal/application/usecase/list_users_usecase.go`, `internal/infrastructure/repository/postgres_user_repository.go` | Alto |
| 6 | CORS: `CORS_ALLOWED_ORIGINS=*` ecoa a `Origin` do request junto de `Access-Control-Allow-Credentials: true`, o que equivale a permitir credenciais para qualquer origem. | `internal/infrastructure/http/middleware/cors_middleware.go` | Médio |
| 7 | Detalhe do erro de HMAC é devolvido ao cliente (`"Assinatura HMAC inválida: %v"`), diferenciando timestamp fora da janela de assinatura errada. | `internal/infrastructure/http/middleware/sync_middleware.go` | Baixo |
| 8 | `GetAllPublicKeysJWK` segura `mu.RLock()` e chama `GetPublicKeyJWK` → `GetPublicKey` → `GetCurrentKeyID`, que fazem `RLock()` de novo. RLock reentrante trava se um `Lock()` (ex.: `RotateKey`) estiver na fila. | `internal/application/service/rsa_key_service.go` | Médio |
| 9 | Sem rate limiting em `/authenticate`, `/refresh` e `/password-reset/*` (brute force de senha e de token de reset). | `cmd/api/main.go` | Médio |
| 10 | `http.Server` sem `ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout`/`IdleTimeout` (Slowloris) e sem graceful shutdown (`signal.NotifyContext` + `server.Shutdown`). | `cmd/api/main.go` | Médio |
| 11 | O `kid` do JWT é usado como nome de arquivo ao carregar chaves; se algum dia vier de input externo precisa de sanitização de path. Hoje é derivado só de arquivos locais. | `rsa_key_service.go` | Baixo |
| 12 | Migrations rodam automaticamente no boot da API com o mesmo usuário de runtime (precisa DDL). Preferível usuário separado para migração. | `cmd/api/main.go`, `internal/infrastructure/migration/` | Baixo |
