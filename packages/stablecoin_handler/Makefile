.PHONY: print-coverage test coverage compile publish

print-coverage:
	@if [ ! -f .coverage_map.mvcov ]; then $(MAKE) coverage; fi;
	aptos move coverage source --module $(word 2,$(MAKECMDGOALS))  --dev

test:
	aptos move test --dev

coverage:
	aptos move test --coverage --dev

compile:
	aptos move compile --named-addresses stablecoin_handler=stablecoin_handler,token_messenger_minter_v2=token_messenger_minter_v2,aptos_extensions=aptos_extensions,stablecoin=stablecoin

publish:
	aptos move publish --profile $(profile) --named-addresses stablecoin_handler=stablecoin_handler,token_messenger_minter_v2=token_messenger_minter_v2,aptos_extensions=aptos_extensions,stablecoin=stablecoin --assume-yes

# Prevents make from thinking the arguments are actual targets
%:
	@:


