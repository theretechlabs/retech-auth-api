.PHONY: help build run test test-coverage lint clean docker-up docker-down docker-logs docker-app docker-app-logs docker-shell docker-rebuild migrate-up migrate-down seed setup dev deps tenant-setup setup-master

help: ## Mostra esta ajuda
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Compila a aplicação
	@echo "Compilando aplicação..."
	@go build -o bin/retech-auth-api cmd/api/main.go

run: ## Executa a aplicação
	@echo "Executando aplicação..."
	@go run cmd/api/main.go

test: ## Executa os testes
	@echo "Executando testes..."
	@go test -v ./...

test-coverage: ## Executa os testes com coverage
	@echo "Executando testes com coverage..."
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html

lint: ## Executa golangci-lint (mesma config do CI)
	@golangci-lint run ./...

clean: ## Remove arquivos compilados
	@echo "Limpando..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html

docker-up: ## Sobe o banco de dados local
	@echo "Subindo banco de dados..."
	@docker-compose up postgres -d

docker-down: ## Para o banco de dados local
	@echo "Parando banco de dados..."
	@docker-compose down

docker-logs: ## Mostra os logs do banco de dados
	@docker-compose logs -f postgres

docker-app: ## Sobe banco E aplicação no Docker
	@echo "Subindo tudo no Docker..."
	@docker-compose up -d --build
	@echo "Aguardando banco inicializar..."
	@sleep 5
	@echo "✅ Aplicação rodando em http://localhost:8080"

docker-app-logs: ## Mostra logs da aplicação no Docker
	@docker-compose logs -f app

docker-shell: ## Abre shell no container da aplicação
	@docker-compose exec app sh

docker-rebuild: ## Reconstrói e sobe a aplicação
	@docker-compose up -d --build

migrate-up: ## Executa as migrations
	@echo "Executando migrations..."
	@go run cmd/migrate/main.go up

migrate-down: ## Reverte as migrations
	@echo "Revertendo migrations..."
	@go run cmd/migrate/main.go down

seed: ## Executa os seeds
	@echo "Executando seeds..."
	@go run cmd/seed/main.go

setup: docker-up migrate-up seed ## Setup completo (docker + migrations + seeds)
	@echo "Setup completo realizado com sucesso!"

dev: docker-up ## Ambiente de desenvolvimento completo (Go local)
	@echo "Aguardando banco de dados..."
	@sleep 3
	@make migrate-up
	@make seed
	@make run

deps: ## Instala as dependências
	@echo "Instalando dependências..."
	@go mod download
	@go mod tidy

tenant-setup: ## Executa o assistente interativo de tenant/usuário/roles
	@go run cmd/tools/tenant_setup/main.go

setup-master: ## Configura usuário Master para retech-fin-admin (SQL direto)
	@echo "⚙️  Configurando usuário Master..."
	@go run cmd/tools/setup_master/main.go

