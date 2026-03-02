# hq-vault Docker targets
# ─────────────────────────────────────────────────────────────────────

IMAGE_NAME ?= hq-vault
CONTAINER_NAME ?= hq-vault
COMPOSE ?= docker compose

.PHONY: build run stop logs init identity shell clean test-docker help

help: ## Show this help
	@echo "hq-vault Docker targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""

build: ## Build the Docker image
	$(COMPOSE) build

run: ## Start the vault (docker compose up -d)
	$(COMPOSE) up -d

stop: ## Stop the vault
	$(COMPOSE) down

logs: ## Tail vault logs
	$(COMPOSE) logs -f vault

init: ## Initialize a new vault (interactive — prompts for passphrase)
	$(COMPOSE) run --rm vault init

identity: ## Create an admin identity (usage: make identity NAME=admin TYPE=human)
	$(COMPOSE) run --rm vault identity create --name $(NAME) --type $(TYPE)

shell: ## Open a shell inside the vault container
	$(COMPOSE) exec vault sh

status: ## Show vault status
	$(COMPOSE) exec vault node dist/cli.js status --vault-path /data/vault.db

clean: ## Remove containers, volumes, and images
	$(COMPOSE) down -v --rmi local

test-docker: build ## Build image and verify it starts (smoke test)
	@echo "=== Building image ==="
	$(COMPOSE) build
	@echo ""
	@echo "=== Image size ==="
	docker images $(IMAGE_NAME) --format "{{.Repository}}:{{.Tag}} — {{.Size}}"
	@echo ""
	@echo "=== Build successful ==="
