# Retech Auth API

Serviço central de **autenticação e autorização** para os produtos **The Retech**, em Go, com Clean Architecture, RBAC, JWT (RS256) e suporte multi-aplicação (multi-tenant).

## Visão geral

- Autenticação de usuários por aplicação (`application_code`)
- RBAC com permissões compatíveis com CASL (subject/action)
- Tokens JWT assinados com RSA; JWKS para validação em APIs consumidoras
- Manifest + sync para permissões e roles base declarativas
- Roles de sistema protegidas contra edição indevida via API

## Módulo Go

```
github.com/theretech/retech-auth-api
```

## Documentação da API

Com a API em execução:

- Redoc: `/docs` e `/docs/v1`
- Especificação OpenAPI: [`public/openapi-v1.yaml`](public/openapi-v1.yaml) (versão principal) e [`public/openapi.yaml`](public/openapi.yaml)

## Pré-requisitos

- Go 1.23+
- Docker e Docker Compose (para PostgreSQL local ou stack completa)
- Make (opcional)

## Configuração

```bash
cp .env.example .env
# Ajuste BOOTSTRAP_SECRET, senhas de banco e demais variáveis.
```

Variáveis obrigatórias estão descritas em [`.env.example`](.env.example). O bootstrap HMAC de `/applications/sync` usa `BOOTSTRAP_SECRET` no servidor; ferramentas cliente podem expor o mesmo valor como `RETECHAUTH_BOOTSTRAP_SECRET`.

## Início rápido (banco no Docker, API local)

```bash
make docker-up    # sobe só o PostgreSQL
make migrate-up
make seed
make run
```

## Comandos Make úteis

| Alvo | Descrição |
|------|-----------|
| `make help` | Lista todos os alvos |
| `make docker-up` / `make docker-down` | Sobe/para o Postgres |
| `make migrate-up` | Aplica migrations |
| `make seed` | Dados iniciais de demonstração |
| `make run` | Sobe a API |
| `make tenant-setup` | Assistente interativo de provisionamento |
| `make setup-master` | Garante app `retech-fin-admin` + usuário master via SQL |

## Testar com cURL

Após `make seed`:

```bash
curl -s -X POST http://localhost:8080/v1/authenticate \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@theretech.local",
    "password": "Master@123",
    "application_code": "retech-fin-admin"
  }'
```

Credenciais padrão do seed:

- **Application code:** `retech-fin-admin`
- **E-mail:** `admin@theretech.local`
- **Senha:** `Master@123`

## Build e testes

```bash
make build
go test ./...
```

## Docker de produção

Imagem multi-stage em [`Dockerfile`](Dockerfile). Em runtime, injete todas as variáveis obrigatórias (equivalente a `.env.example`) e monte um volume persistente para `JWT_RSA_KEYS_DIR` se necessário.

---

Desenvolvido para o ecossistema The Retech.
