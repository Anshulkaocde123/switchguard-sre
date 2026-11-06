# ==============================================================================
# SwitchGuard SRE — Master Hackathon Makefile
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

.PHONY: help build install reset setup test test-unit chaos audit attack-demo demo simulate storm dashboard serve clean all

help: ## Show this help menu
	@echo ""
	@echo -e "${CYAN}${BOLD}SwitchGuard SRE — Master Automation & Verification CLI${RESET}"
	@echo -e "${YELLOW}Confidential Multi-Agent Autonomous War Room on Switch Console & Antigravity ACP${RESET}"
	@echo ""
	@echo -e "${BOLD}Available Targets:${RESET}"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  ${GREEN}%-16s${RESET} %s\n", $$1, $$2}'
	@echo ""

all: build install reset test audit ## Full pipeline: build, reset sandbox, run 7-layer suite & audit

build: ## Build Rust AST & Security CLI in release mode with LTO
	@echo -e "${CYAN}[*] Building switchguard-cli (LTO + opt-level=3)...${RESET}"
	@cargo build --release --manifest-path switchguard-cli/Cargo.toml
	@mkdir -p $$HOME/.local/bin $$HOME/.opencode/bin $$HOME/bin
	@cp switchguard-cli/target/release/switchguard-cli $$HOME/.local/bin/switchguard-cli
	@cp switchguard-cli/target/release/switchguard-cli $$HOME/.opencode/bin/switchguard-cli
	@cp switchguard-cli/target/release/switchguard-cli $$HOME/bin/switchguard-cli
	@chmod +x $$HOME/.local/bin/switchguard-cli $$HOME/.opencode/bin/switchguard-cli $$HOME/bin/switchguard-cli
	@echo -e "${GREEN}[✔] Rust binary compiled & installed to PATH successfully.${RESET}"

install: build ## Alias for build & install

reset: ## Reset workspace/sandbox-app to clean baseline state (<2 seconds)
	@echo -e "${CYAN}[*] Executing clean-room reset script...${RESET}"
	@bash scripts/setup_demo.sh

setup: reset ## Alias for reset

test: ## Run the full 28-assertion 7-layer verification mega suite
	@echo -e "${CYAN}[*] Running 7-Layer Red-Team Verification Mega Suite...${RESET}"
	@python3 scripts/mega_sre_test_suite.py

test-unit: ## Run pytest unit tests on sandbox-app (28 tests)
	@echo -e "${CYAN}[*] Running sandbox-app pytest suite...${RESET}"
	@pytest workspace/sandbox-app -v

attack-demo: ## Simulate INC-8043 live prompt-injection attack & AST-SEC-02 block
	@python3 scripts/simulate_incident.py --scenario prompt-injection

chaos: ## Run red-team security chaos tests (Scenarios 1-5)
	@echo -e "${CYAN}[*] Running Security Chaos Drills (PII, RCE, Blast-Radius, Injection)...${RESET}"
	@python3 scripts/security_chaos_test.py

audit: ## 1-command verification of SHA-256 release audit log hash chain
	@echo -e "${CYAN}[*] Verifying cryptographic release audit hash chain...${RESET}"
	@switchguard-cli verify-audit workspace/release-ops/RELEASE_AUDIT.log

demo: ## Launch interactive telemetry crash simulator for live demos
	@python3 scripts/simulate_incident.py --interactive

simulate: ## Sequentially fire all incident scenarios
	@python3 scripts/simulate_crash.py --scenario inc-8041
	@python3 scripts/simulate_crash.py --scenario inc-8042
	@python3 scripts/simulate_crash.py --scenario inc-8043

storm: ## Simulate a 500-alert crash storm verifying O(1) deduplication
	@python3 scripts/simulate_crash.py --storm 500

dashboard: ## Re-generate the executive HTML dashboard (docs/index.html)
	@echo -e "${CYAN}[*] Generating executive HTML dashboard...${RESET}"
	@python3 workspace/release-ops/cut_release.py --dashboard
	@echo -e "${GREEN}[✔] Dashboard generated at docs/index.html${RESET}"

serve: ## Serve docs/index.html locally on port 8000
	@echo -e "${CYAN}[*] Serving dashboard at http://localhost:8000/ ...${RESET}"
	@echo -e "${YELLOW}Open http://localhost:8000 in your browser. Press Ctrl+C to stop.${RESET}"
	@python3 -m http.server 8000 --directory docs

clean: ## Clean build target, pytest cache, and temporary files
	@echo -e "${CYAN}[*] Cleaning temporary files...${RESET}"
	@rm -rf .pytest_cache workspace/sandbox-app/.pytest_cache switchguard-cli/target
	@echo -e "${GREEN}[✔] Workspace cleaned.${RESET}"
