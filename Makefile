.PHONY: setup install-aptos test compile-scripts message-transmitter-test message-transmitter-coverage token-messenger-minter-test \
token-messenger-minter-coverage verify-message-transmitter-coverage verify-token-messenger-minter-coverage compile-message-transmitter-scripts compile-token-messenger-minter-script

setup: install-aptos
	git submodule update --init --recursive

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

test: message-transmitter-test token-messenger-minter-test

compile-scripts: compile-message-transmitter-scripts compile-token-messenger-minter-scripts

message-transmitter-test:
	aptos move test --package-dir packages/message_transmitter --dev

message-transmitter-coverage:
	aptos move test --package-dir packages/message_transmitter --coverage --dev

token-messenger-minter-test:
	aptos move test --package-dir packages/token_messenger_minter --dev

token-messenger-minter-coverage:
	aptos move test --package-dir packages/token_messenger_minter --coverage --dev

verify-message-transmitter-coverage:
	@coverage=$$(aptos move test --package-dir packages/message_transmitter --coverage --dev | grep "Move Coverage:" | grep -Eo "[0-9]+" | head -1); \
	if [ $$coverage -eq 100 ]; then \
		echo "Test Coverage is $$coverage%"; \
	else \
		echo "Test Coverage is only $$coverage%. Should be at least 99%"; \
		exit 1; \
	fi

verify-token-messenger-minter-coverage:
	@coverage=$$(aptos move test --package-dir packages/token_messenger_minter --coverage --dev | grep "Move Coverage:" | grep -Eo "[0-9]+" | head -1); \
	if [ $$coverage -eq 100 ]; then \
		echo "Test Coverage is $$coverage%"; \
	else \
		echo "Test Coverage is only $$coverage%. Should be at least 99%"; \
		exit 1; \
	fi

compile-message-transmitter-scripts:
	aptos move compile --package-dir packages/message_transmitter --dev

compile-token-messenger-minter-scripts:
	aptos move compile --package-dir packages/token_messenger_minter --dev

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
