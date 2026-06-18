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

.PHONY: proto-check
proto-check: proto ## Verify committed generated bindings are up to date.
	git diff --exit-code -- server/gen \
		|| { echo "server/gen is stale; run 'make proto' and commit"; exit 1; }

## ---- build ----

.PHONY: build-server
build-server: ## Build the Go server binary.
	cd server && go build -o bin/kseal-server ./cmd/kseal-server

.PHONY: build-rust
build-rust: ## Build the Rust trust core + FFI (release): default artifacts in target/release, hardened (obfuscated) verification build in target/obfuscated.
	cd sdk/rust-core && cargo build --release
	cd sdk/rust-core && cargo build --release --features obfuscate-strings --target-dir target/obfuscated

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
test-rust: ## Run Rust tests (default + hardened string-obfuscation feature + vm-spike decision spike).
	cd sdk/rust-core && cargo test
	cd sdk/rust-core && cargo test --features obfuscate-strings
	cd sdk/rust-core && cargo test --features vm-spike

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
	cd sdk/rust-core && cargo clippy --all-targets --features obfuscate-strings -- -D warnings
	cd sdk/rust-core && cargo clippy --all-targets --features vm-spike -- -D warnings

## ---- docker (prod-mirroring local stack) ----

.PHONY: up
up: ## Bring up the full stack and wait until the server is ready.
	docker compose up --build -d --wait
	@echo "kseal is up:"
	@echo "  server   http://localhost:8080  (/healthz /readyz /metrics)"
	@echo "  console  http://localhost:5173"

.PHONY: down
down: ## Stop the stack (keeps the Postgres volume).
	docker compose down

.PHONY: clean
clean: ## Stop the stack AND delete volumes (destroys Postgres data).
	docker compose down -v

.PHONY: logs
logs: ## Tail logs from all services.
	docker compose logs -f

.PHONY: ps
ps: ## Show stack status + health.
	docker compose ps

.PHONY: smoke
smoke: ## Bring up the stack and assert server /readyz + console respond.
	docker compose up --build -d --wait
	@echo "==> server /readyz"; curl -fsS http://localhost:8080/readyz && echo
	@echo "==> server /healthz"; curl -fsS http://localhost:8080/healthz && echo
	@echo "==> console /"; curl -fsS -o /dev/null -w '%{http_code}\n' http://localhost:5173/
	@echo "smoke OK"

# Backwards-compatible aliases.
.PHONY: docker-up docker-down docker-clean
docker-up: up   ## Alias for `up`.
docker-down: down ## Alias for `down`.
docker-clean: clean ## Alias for `clean`.

## ---- deploy artifact validation ----

.PHONY: deploy-lint
deploy-lint: ## Lint the Helm chart + validate rendered manifests (needs helm, kubeconform).
	helm lint deploy/helm/kseal
	@for env in dev staging prod; do \
		echo "==> kubeconform ($$env)"; \
		helm template kseal deploy/helm/kseal -f deploy/helm/kseal/values-$$env.yaml \
			| kubeconform -strict -summary -ignore-missing-schemas -kubernetes-version 1.29.0; \
	done

.PHONY: tf-validate
tf-validate: ## terraform fmt -check + validate every module and env (no apply).
	terraform -chdir=deploy/terraform fmt -check -recursive
	@for dir in deploy/terraform/modules/* deploy/terraform/envs/*; do \
		echo "==> terraform validate $$dir"; \
		terraform -chdir="$$dir" init -backend=false -input=false >/dev/null; \
		terraform -chdir="$$dir" validate; \
	done

## ---- on-prem / air-gapped bundle ----

ONPREM_VERSION ?= $(shell awk '/^appVersion:/{gsub(/"/,"",$$2); print $$2}' deploy/helm/kseal/Chart.yaml)
ONPREM_DIST    := deploy/onprem/dist
ONPREM_STAGE   := $(ONPREM_DIST)/kseal-onprem-$(ONPREM_VERSION)
ONPREM_TARBALL := $(ONPREM_DIST)/kseal-onprem-$(ONPREM_VERSION).tgz

.PHONY: bundle-onprem
bundle-onprem: ## Package the air-gapped on-prem verifier bundle (Helm chart + compose + docs) into a tarball.
	@command -v helm >/dev/null || { echo "helm is required"; exit 1; }
	rm -rf "$(ONPREM_STAGE)"
	mkdir -p "$(ONPREM_STAGE)/helm" "$(ONPREM_STAGE)/docs"
	# Compose + Helm values variant, image list, mirror script, env template.
	cp deploy/onprem/docker-compose.yml deploy/onprem/values-onprem.yaml \
		deploy/onprem/images.txt deploy/onprem/mirror-images.sh \
		deploy/onprem/.env.example deploy/onprem/README.md "$(ONPREM_STAGE)/"
	# Versioned, self-contained Helm chart package.
	helm package deploy/helm/kseal --destination "$(ONPREM_STAGE)/helm" >/dev/null
	# Deployment + DR docs travel with the bundle.
	cp docs/deployment-onprem.md docs/deployment-disaster-recovery.md "$(ONPREM_STAGE)/docs/"
	# Reproducible tarball (sorted, fixed owner/mtime) + checksum.
	tar --sort=name --owner=0 --group=0 --numeric-owner \
		--mtime='@0' -czf "$(ONPREM_TARBALL)" \
		-C "$(ONPREM_DIST)" "kseal-onprem-$(ONPREM_VERSION)"
	cd "$(ONPREM_DIST)" && sha256sum "kseal-onprem-$(ONPREM_VERSION).tgz" > "kseal-onprem-$(ONPREM_VERSION).tgz.sha256"
	@echo "bundle: $(ONPREM_TARBALL)"
	@cat "$(ONPREM_TARBALL).sha256"
