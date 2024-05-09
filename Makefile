-include .env

clean  :; forge clean

build:; forge build

test :; forge test 

snapshot :; forge snapshot

format :; forge fmt

NETWORK_ARGS := --legacy --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast --gas-price 27000000001 --priority-gas-price 2000000001 --verify --etherscan-api-key $(ETHERSCAN_API_KEY) -vvvvv

deploy:
	@forge script script/Deploy.s.sol:Deploy $(NETWORK_ARGS)

register:
	@forge script script/Register.s.sol:Register $(NETWORK_ARGS)
