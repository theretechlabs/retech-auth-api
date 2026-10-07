# Build (docker compose / deploy)
FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
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
