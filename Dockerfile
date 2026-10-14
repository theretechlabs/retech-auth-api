# Build (docker compose / deploy)
FROM golang:1.26-alpine AS builder
WORKDIR /app
RUN apk add --no-cache git
COPY go.mod go.sum ./
# retech-authkit é módulo privado: o proxy público só tem versões antigas em
# cache. O Railway passa as variáveis do serviço como build args declarados
# com ARG; com GITHUB_TOKEN (fine-grained, só leitura de conteúdo no
# retech-auth-kit) o git autentica. O token vive só neste estágio builder, que
# não vai para a imagem final. ARG em vez de --mount=type=secret: o builder
# do Railway não aceita RUN --mount.
ARG GITHUB_TOKEN
ENV GOPRIVATE=github.com/theretechlabs
RUN if [ -n "$GITHUB_TOKEN" ]; then \
      git config --global url."https://x-access-token:${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"; \
    fi \
    && go mod download \
    && rm -f /root/.gitconfig
COPY . .
RUN CGO_ENABLED=0 go build -o /retech-auth-api ./cmd/api

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S app && adduser -S -G app -H -s /sbin/nologin app
WORKDIR /app
COPY --from=builder /retech-auth-api /usr/local/bin/retech-auth-api
COPY --chown=app:app public ./public
# Diretório padrão de chaves RSA; em produção monte um volume persistente aqui
# (ou aponte JWT_RSA_KEYS_DIR para outro caminho gravável pelo usuário app).
RUN mkdir -p /app/keys && chown -R app:app /app
ENV PORT=8080
EXPOSE 8080
USER app
ENTRYPOINT ["/usr/local/bin/retech-auth-api"]
