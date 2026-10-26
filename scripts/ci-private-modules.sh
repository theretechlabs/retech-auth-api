#!/usr/bin/env sh
# Configura o git do runner para baixar módulos Go privados da org
# (github.com/theretechlabs/*). Usado só no CI; no Railway o Dockerfile faz o
# equivalente. Exige AUTHKIT_READ_TOKEN (PAT fine-grained, leitura de conteúdo
# no retech-authkit). Sem o token, avisa e segue: o go mod download falha
# depois com erro explícito em vez de um 401 silencioso aqui.
set -eu

if [ -z "${AUTHKIT_READ_TOKEN:-}" ]; then
  echo "::warning::AUTHKIT_READ_TOKEN ausente; módulos privados não vão resolver"
  exit 0
fi

git config --global url."https://x-access-token:${AUTHKIT_READ_TOKEN}@github.com/".insteadOf "https://github.com/"
echo "git configurado para módulos privados de github.com/theretechlabs"
