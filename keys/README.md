# Chaves RSA (JWT)

Este diretório é o valor padrão de `JWT_RSA_KEYS_DIR` em desenvolvimento.
Ele existe no repositório apenas como marcador (`.gitkeep`): **nenhuma chave
privada deve ser commitada**. O `.gitignore` bloqueia `*.pem`, `*.key` e tudo
dentro de `keys/` exceto este README.

## Como funciona

- Na inicialização, `internal/application/service/rsa_key_service.go` lê todos
  os arquivos `*.pem` do diretório. O nome do arquivo (sem extensão) vira o
  `kid` do token; a chave com maior `kid` lexicográfico é a ativa.
- Se não houver nenhuma chave, a aplicação **gera uma automaticamente**
  (RSA 2048, PKCS#1, permissão `0600`) e a salva em `<kid>.pem`.
- As chaves públicas são expostas em JWKS para os clientes validarem RS256.

## Gerar uma chave localmente

Opção 1 — deixar a aplicação gerar (recomendado em dev): basta subir a API
com `JWT_RSA_KEYS_DIR=./keys`.

Opção 2 — gerar manualmente:

```bash
openssl genrsa -out keys/dev.pem 2048
```

O arquivo precisa estar em PEM `RSA PRIVATE KEY` (PKCS#1). Se o OpenSSL gerar
`PRIVATE KEY` (PKCS#8), converta:

```bash
openssl rsa -in keys/dev.pem -out keys/dev.pem -traditional
```

## Produção

- O diretório apontado por `JWT_RSA_KEYS_DIR` **precisa ser um volume
  persistente** (ou a chave deve ser injetada a partir de um secret manager no
  start do container). Se o diretório for efêmero, cada deploy gera uma chave
  nova e invalida todos os tokens emitidos anteriormente.
- Nunca copie chaves para dentro da imagem Docker.
- Para rotacionar, adicione um novo `.pem` com nome lexicograficamente maior e
  mantenha o antigo até os tokens em circulação expirarem; depois remova-o.
