.PHONY: all relay agent clean test e2e

# Build targets
all: relay agent

relay:
	@echo "Building zgate-relay..."
	cd relay && CGO_ENABLED=0 go build -ldflags="-s -w" -o ../bin/zgate-relay .

agent:
	@echo "Building zgate-agent..."
	cd agent && CGO_ENABLED=0 go build -ldflags="-s -w" -o ../bin/zgate-agent .

clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/

# Test targets
test:
	@echo "Running unit tests..."
	cd relay && go test ./...
	cd agent && go test ./...

e2e:
	@echo "Starting E2E Test..."
	docker compose down -v
	docker compose up --build -d
	@echo "Waiting for tunnel to stabilize (max 30s)..."
	@timeout=30; \
	while ! docker compose exec agent-1 ping -c 1 -W 1 8.8.8.8 > /dev/null 2>&1; do \
		timeout=$$((timeout-1)); \
		if [ $$timeout -le 0 ]; then echo "Timeout waiting for connectivity"; exit 1; fi; \
		echo "Waiting... ($$timeout remaining)"; \
		sleep 1; \
	done
	@echo "Connectivity Established! Running Full Ping Test (8.8.8.8)..."
	docker compose exec agent-1 ping -c 4 8.8.8.8
	@echo "Running Ping Test (1.1.1.1)..."
	docker compose exec agent-1 ping -c 4 1.1.1.1
	@echo "E2E Test Passed!"

# Development targets
.PHONY: certs
certs:
	@echo "Generating certificates..."
	./scripts/generate-certs.sh

.PHONY: dev-up
dev-up:
	@echo "Starting development environment..."
	docker compose up -d

.PHONY: dev-down
dev-down:
	@echo "Stopping development environment..."
	docker compose down

.PHONY: logs-relay
logs-relay:
	docker compose logs -f relay

.PHONY: logs-agent
logs-agent:
	docker compose logs -f agent
