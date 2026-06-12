# kseal — root build orchestration.
#
# Targets are thin wrappers over the per-component toolchains (buf, go, cargo,
# npm) so the whole platform can be built, tested, and run from one place.

SHELL := /usr/bin/env bash
GOBIN := $(shell go env GOPATH)/bin
export PATH := $(GOBIN):$(PATH)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help.
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

## ---- protobuf ----

.PHONY: proto-tools
proto-tools: ## Install protobuf codegen plugins (buf, protoc-gen-go, connect).
	GOTOOLCHAIN=auto go install github.com/bufbuild/buf/cmd/buf@v1.55.1
	GOTOOLCHAIN=auto go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.34.2
	GOTOOLCHAIN=auto go install connectrpc.com/connect/cmd/protoc-gen-connect-go@v1.16.2

.PHONY: proto
proto: ## Generate Go + Connect bindings from proto schemas.
	cd proto && ./generate.sh

.PHONY: proto-lint
proto-lint: ## Lint protobuf schemas.
	cd proto && buf lint

## ---- build ----

.PHONY: build-server
build-server: ## Build the Go server binary.
	cd server && go build -o bin/kseal-server ./cmd/kseal-server

.PHONY: build-rust
build-rust: ## Build the Rust trust core + FFI (release).
	cd sdk/rust-core && cargo build --release

.PHONY: build-console
build-console: ## Build the React dashboard.
	cd web/console && npm ci && npm run build

.PHONY: build
build: proto build-server build-rust ## Build server + rust core.

## ---- test ----

.PHONY: test-server
test-server: ## Run Go tests.
	cd server && go test ./...

.PHONY: test-rust
test-rust: ## Run Rust tests.
	cd sdk/rust-core && cargo test

.PHONY: test-integration
test-integration: ## Run end-to-end integration tests.
	cd tests && go test ./...

.PHONY: test
test: test-server test-rust ## Run server + rust unit tests.

## ---- lint ----

.PHONY: lint
lint: proto-lint ## Run all linters.
	cd server && go vet ./...
	cd sdk/rust-core && cargo clippy --all-targets -- -D warnings

## ---- docker ----

.PHONY: docker-up
docker-up: ## Start the full stack (server, postgres, redis, console).
	docker compose up --build -d

.PHONY: docker-down
docker-down: ## Stop the stack (keeps the Postgres volume).
	docker compose down

.PHONY: docker-clean
docker-clean: ## Stop the stack AND delete volumes (destroys Postgres data).
	docker compose down -v
