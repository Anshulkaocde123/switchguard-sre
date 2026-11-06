# ==============================================================================
# SwitchGuard SRE — Master Hackathon Makefile
# Autonomous Incident Response & Cryptographic Proof-of-Hotfix Ledger
# ==============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

# Colors
CYAN   := \033[36m
GREEN  := \033[32m
YELLOW := \033[33m
RED    := \033[31m
BOLD   := \033[1m
RESET  := \033[0m

.PHONY: help build install reset setup test test-unit attack-demo storm-demo verify-chain audit demo simulate storm dashboard serve clean all

help: ## Show this help menu
	@echo ""
	@echo -e "${CYAN}${BOLD}SwitchGuard SRE — Master Automation & Verification CLI${RESET}"
	@echo -e "${YELLOW}Confidential Multi-Agent Autonomous War Room on Switch Console & Antigravity ACP${RESET}"
	@echo ""
	@echo -e "${BOLD}Available Targets:${RESET}"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  ${GREEN}%-16s${RESET} %s\n", $$1, $$2}'
	@echo ""

all: build reset test verify-chain ## Full pipeline: build, reset, test mega suite, and verify audit chain

build: ## Build Rust AST & Security CLI in release mode with LTO and copy to PATH
	@echo -e "${CYAN}[*] Building switchguard-cli v0.4.0 (LTO + opt-level=3)...${RESET}"
	@cargo build --release -j 2 --manifest-path switchguard-cli/Cargo.toml
	@mkdir -p $$HOME/.local/bin $$HOME/.opencode/bin $$HOME/bin
	@cp switchguard-cli/target/release/switchguard-cli $$HOME/.local/bin/switchguard-cli
	@cp switchguard-cli/target/release/switchguard-cli $$HOME/.opencode/bin/switchguard-cli
	@cp switchguard-cli/target/release/switchguard-cli $$HOME/bin/switchguard-cli
	@chmod +x $$HOME/.local/bin/switchguard-cli $$HOME/.opencode/bin/switchguard-cli $$HOME/bin/switchguard-cli
	@echo -e "${GREEN}[✔] Rust binary compiled & installed to PATH successfully.${RESET}"

install: build ## Alias for build

reset: ## Reset repository & sandbox-app to clean baseline state (<1s)
	@echo -e "${CYAN}[*] Executing clean-room reset script...${RESET}"
	@bash scripts/setup_demo.sh

setup: reset ## Alias for reset

test: ## Run the full 30-assertion 7-layer verification mega suite
	@echo -e "${CYAN}[*] Running 7-Layer Red-Team Verification Mega Suite...${RESET}"
	@python3 scripts/mega_sre_test_suite.py

test-unit: ## Run pytest unit tests on sandbox-app (37 tests)
	@echo -e "${CYAN}[*] Running sandbox-app pytest suite...${RESET}"
	@pytest workspace/sandbox-app -v

attack-demo: ## Simulate INC-8043 live prompt-injection attack & AST-SEC-02 block
	@python3 scripts/simulate_incident.py --scenario prompt-injection

storm-demo: ## Simulate 32 parallel threads alert storm demonstrating 96.8% token savings
	@python3 scripts/simulate_incident.py --scenario alert-storm

verify-chain: ## Cryptographically verify SHA-256 release audit log hash chain
	@python3 scripts/simulate_incident.py --verify-chain

audit: verify-chain ## Alias for verify-chain

demo: ## Launch interactive incident and red-team simulator menu
	@python3 scripts/simulate_incident.py --interactive

simulate: ## Run INC-8041 demonstration
	@python3 scripts/simulate_incident.py --scenario inc-8041

storm: storm-demo ## Alias for storm-demo

dashboard: ## Re-generate the executive HTML dashboard (docs/index.html)
	@echo -e "${CYAN}[*] Generating executive HTML dashboard...${RESET}"
	@python3 workspace/release-ops/cut_release.py --dashboard
	@echo -e "${GREEN}[✔] Dashboard generated at docs/index.html${RESET}"

serve: ## Serve docs/index.html locally on port 8000
	@echo -e "${CYAN}[*] Serving dashboard at http://localhost:8000/ ...${RESET}"
	@echo -e "${YELLOW}Open http://localhost:8000 in your browser. Press Ctrl+C to stop.${RESET}"
	@python3 -m http.server 8000 --directory docs

clean: ## Clean build target, pytest caches, and temporary lock files
	@echo -e "${CYAN}[*] Cleaning temporary files...${RESET}"
	@rm -rf .pytest_cache workspace/sandbox-app/.pytest_cache switchguard-cli/target
	@echo -e "${GREEN}[✔] Workspace cleaned.${RESET}"
