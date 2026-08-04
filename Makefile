.PHONY: setup setup-v2 install-aptos test test-v1 test-v2 \
        compile-scripts compile-scripts-v1 compile-scripts-v2 \
        coverage coverage-v1 coverage-v2 \
        coverage-verify coverage-verify-v1 coverage-verify-v2 \
        verify-metadata

SHELL := /bin/bash

setup: install-aptos
	git submodule update --init --recursive

# Interim setup for V2 builds. Applies patches/stablecoin-aptos-v2.patch, which
# aligns the stablecoin-aptos submodule's AptosFramework revision with the one
# used by the V2 CCTP packages (they must match for a shared build graph to
# compile). Remove this target and the patch once circlefin/stablecoin-aptos
# ships a V2-compatible release and the submodule is bumped to it.
# Idempotent: safe to re-run (skips if the patch is already applied).
setup-v2: setup
	@cd stablecoin-aptos && \
	if git apply --reverse --check ../patches/stablecoin-aptos-v2.patch >/dev/null 2>&1; then \
		echo "stablecoin-aptos v2 patch already applied; skipping"; \
	else \
		git apply ../patches/stablecoin-aptos-v2.patch && echo "Applied stablecoin-aptos v2 patch"; \
	fi

install-aptos:
	@arch=$$(uname -m); \
	if [ "$$arch" = "arm64" ]; then \
		if ! command -v brew >/dev/null 2>&1; then \
			echo "Please install brew."; \
			exit 1; \
		fi; \
		brew install aptos; \
		brew install jq; \
	else \
		if [ ! -f versions.sh ]; then \
			echo "Please ensure versions.sh exists in top-level of repository."; \
			exit 1; \
		fi; \
		. ./versions.sh; \
		if [ -z "$$APTOS_CLI_VERSION" ]; then \
			echo "Please ensure that version is set for APTOS_CLI_VERSION in versions.sh."; \
			exit 1; \
		fi; \
		curl -sSfL -o /tmp/aptos.zip "https://github.com/aptos-labs/aptos-core/releases/download/aptos-cli-v$$APTOS_CLI_VERSION/aptos-cli-$$APTOS_CLI_VERSION-Ubuntu-22.04-x86_64.zip"; \
		sudo unzip /tmp/aptos.zip -d /usr/local/bin; \
		sudo chmod +x /usr/local/bin/*; \
	fi

# ============ Pattern Rules ============

%-test:
	aptos move test --package-dir packages/$* --dev

%-coverage:
	aptos move test --package-dir packages/$* --coverage --dev

%-coverage-verify:
	@set -o pipefail; \
	aptos move test --package-dir packages/$* --coverage --dev 2>&1 | tee /tmp/coverage_$*.log; \
	test_exit=$$?; \
	if [ $$test_exit -ne 0 ]; then \
		echo "✗ Tests failed with exit code $$test_exit"; \
		exit $$test_exit; \
	fi; \
	coverage=$$(grep "Move Coverage:" /tmp/coverage_$*.log | grep -Eo "[0-9]+" | head -1); \
	if [ -z "$$coverage" ]; then \
		echo "Error: Could not parse coverage from output"; \
		exit 1; \
	elif [ $$coverage -ge 99 ]; then \
		echo "✓ Test Coverage is $$coverage%"; \
	else \
		echo "✗ Test Coverage is only $$coverage%. Should be at least 99%"; \
		exit 1; \
	fi

%-compile-scripts:
	aptos move compile --package-dir packages/$* --dev

# ============ Aggregate Targets ============
test-v1: message_transmitter-test token_messenger_minter-test

test-v2: cctp_extensions-test message_transmitter_v2-test token_messenger_minter_v2-test stablecoin_handler-test

test: test-v1 test-v2

compile-scripts-v1: message_transmitter-compile-scripts token_messenger_minter-compile-scripts

compile-scripts-v2: cctp_extensions-compile-scripts message_transmitter_v2-compile-scripts token_messenger_minter_v2-compile-scripts stablecoin_handler-compile-scripts

compile-scripts: compile-scripts-v1 compile-scripts-v2

coverage-v1: message_transmitter-coverage token_messenger_minter-coverage

coverage-v2: cctp_extensions-coverage message_transmitter_v2-coverage token_messenger_minter_v2-coverage stablecoin_handler-coverage

coverage: coverage-v1 coverage-v2

coverage-verify-v1: message_transmitter-coverage-verify token_messenger_minter-coverage-verify

coverage-verify-v2: cctp_extensions-coverage-verify message_transmitter_v2-coverage-verify token_messenger_minter_v2-coverage-verify stablecoin_handler-coverage-verify

coverage-verify: coverage-verify-v1 coverage-verify-v2

# ============ Verify Metadata ===========

verify-metadata:
	@if [ -z "$(package)" ] || [ -z "$(package_id)" ] || [ -z "$(url)" ] || [ -z "$(included_artifacts)" ]; then \
		echo "Usage: make verify-package package=\"<package_name>\" package_id=\"<package_id>\" included_artifacts=\"<all/sparse/none>\" url=\"<url>\" [named_addresses=\"<named_addresses>\"]"; \
		exit 1; \
	fi; \
	\
	aptos move verify-package \
		--package-dir "packages/$(package)" \
		--account "$(package_id)" \
		--named-addresses "$(named_addresses)" \
		--included-artifacts "$(included_artifacts)" \
		--url "${url}";
