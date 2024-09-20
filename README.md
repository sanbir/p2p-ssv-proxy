# P2P SSV Proxy contracts

## Description

Their primary purpose of these contracts is to batch and proxy SSV validator registrations so that SSV tokens are abstracted away from the clients. 

## Running tests

```shell
cd p2p-ssv-proxy
cp .env_example .env
# edit .env with the actual values
curl -L https://foundry.paradigm.xyz | bash
source /Users/$USER/.bashrc
foundryup
forge test
```

## SSV validator registration use cases

### 1. Without data generation on the client side
> Client has 100500 ETH and wants to stake it with DVT (SSV) in 1 transaction, preserving custody over withdrawal credentials but delegating validator key management and all the low-level data generation to P2P.

1. Client calls `P2pSsvProxyFactory`'s `addEth` function once. The ETH value should be 100500 ETH.

    The arguments are:
    - **_eth2WithdrawalCredentials** - client's [withdrawal credentials](https://eth2book.info/capella/part2/deposits-withdrawals/withdrawal-processing/#withdrawal-credentials)
    - **_ethAmountPerValidatorInWei** - amount of ETH per validator (exactly 32000000000000000000 (32 ETH in wei) before Pectra)
    - **_clientConfig** - should be in the format {recipient:"0x6Bb8b45a1C6eA816B70d76f83f7dC4f0f87365Ff",basisPoints:9000} for Etherscan if client address is 0x6Bb8b45a1C6eA816B70d76f83f7dC4f0f87365Ff and client should get 90% of total ETH rewards
    - **_referrerConfig** - should be in the format {recipient:"0x81CE71EEB7531AA26073eD0d1110F6F0563C6C7c",basisPoints:600} for Etherscan if referrer address is 0x81CE71EEB7531AA26073eD0d1110F6F0563C6C7c and referrer should get 6% of total ETH rewards. P2P will receive 4% in this case.
    - **_extraData** - any data. Can be empty (""). Intended to be used for MEV relay information, client-specific encrypted data, etc.

    > **Note:** addresses and percentages (basis points) here are for example only. Please double check the actual values before sending any mainnet ETH!!!

Client does not need to do anything else for staking. All the following steps are done by P2P:

2. P2P generates ETH2 deposit data and corresponding SSV shares data for each validator.
3. P2P calls `P2pSsvProxyFactory`'s `makeBeaconDepositsAndRegisterValidators` function for batches up to 50 validators using 
   - the client data from Step 1 (retrived from  `P2pSsvProxyFactory`'s `P2pSsvProxyFactory__EthForSsvStakingDeposited` events and `P2pOrgUnlimitedEthDepositor`'s `P2pOrgUnlimitedEthDepositor__ClientEthAdded` events).
   - the ETH2 deposit data and corresponding SSV shares data generated in Step 2.

4. If P2P did not do the actual staking deposits within 1 day, client can call `P2pOrgUnlimitedEthDepositor`'s `refund` function to get their ETH back.

### 2. [Deprecated] With ETH deposit (with data generation on the client side)

> Client has 3200 ETH and wants to stake it with DVT (SSV), preserving custody over withdrawal credentials and private keys of the validators.
> 

All the steps below can happen client-side without any interaction with P2P servers. SSV API can be used for convenience, although, all the data is also available on-chain.

1. Client generates 100 ETH2 validator private keys on their side. (For example, can be [generated from 1 mnemonic](https://www.npmjs.com/package/@chainsafe/bls-keygen)).
2. Client generates 100 keystore JSON files on their side (encrypted private keys).
3. Client generates 100 ETH2 deposit data JSON files on their side.

Steps 1 - 3 can be done using the native tools (like [staking-deposit-cli](https://github.com/ethereum/staking-deposit-cli) or [wagyu-key-gen](https://github.com/stake-house/wagyu-key-gen)).

1. Client reads a list of addresses of allowed SSV operator owners from **P2pSsvProxyFactory** contract’s `getAllowedSsvOperatorOwners` function. (For example, it can return 4 addresses).
2. Client reads allowed SSV operator IDs from **P2pSsvProxyFactory** contract’s `getAllowedSsvOperatorIds` function providing it with the address of the SSV operator owner from the previous step each time it’s called. (For example, for 4 addresses, `getAllowedSsvOperatorIds` function should be called 4 times. As a result, the client gets 4 SSV operator IDs).
3. Client predicts `FeeDistributor` instance address by reading **`FeeDistributorFactory`**’s `predictFeeDistributorAddress` function. 
    
    Need to provide it with:
    
    - `_referenceFeeDistributor` - address of the template `FeeDistributor` (can be of any type like `ElOnlyFeeDistributor`, `OracleFeeDistributor`, or `ContractWcFeeDistributor`)
    - `_clientConfig` (basis points, client fee recipient address)
    - `_referrerConfig`(basis points, referrer fee recipient address)
4. Client predicts **`P2pSsvProxy`** instance address by reading `P2pSsvProxyFactory`'s `predictP2pSsvProxyAddress` function, providing it with the `FeeDistributor` instance address from the previous step.
5. Client generates 100 SSV keyshares JSON files choosing operator IDs from Step 5 and cluster owner from Step 7. 
    
    (`P2pSsvProxy` instance address is the cluster owner).
    
    [ssv-keys](https://github.com/bloxapp/ssv-keys) tool can be used for generation.
    
6. Client reads operator snapshots from **SSVNetwork** contract’s storage slots. Each operator has its own snapshot.
    
    <aside>
    💡 This can be done using any library with RPC access to Ethereum execution layer blockchain (`eth_getStorageAt` RPC Method, e.g. [ethers.js](https://docs.ethers.org/v5/api/providers/provider/#Provider-getStorageAt), [web3.py](https://web3py.readthedocs.io/en/v5/web3.eth.html#web3.eth.Eth.get_storage_at), etc.).
    
    </aside>
    
    An example of how it’s done using Foundry’s [forge](https://book.getfoundry.sh/forge/):
    
    ```solidity
    function getSnapshot(uint64 operatorId) private view returns(bytes32 snapshot) {
        uint256 p = uint256(keccak256("ssv.network.storage.main")) + 5;
        bytes32 slot1 = bytes32(uint256(keccak256(abi.encode(uint256(operatorId), p))) + 2);
        snapshot = vm.load(ssvNetworkAddress, slot1);
    }
    ```
    
7. Client reads slot #`6836850959782774711213773224022472945316713988199727877409042202683022748181` (DEC) `0x0f1d85405047bdb6b0a60e27531f52a1f7a948613527b9b83a7552558207aa15` (HEX) from **SSVNetwork** contract’s storage.
    
    <aside>
    💡 This can be done using any library with RPC access to Ethereum execution layer blockchain (`eth_getStorageAt` ****RPC Method, e.g. [ethers.js](https://docs.ethers.org/v5/api/providers/provider/#Provider-getStorageAt), [web3.py](https://web3py.readthedocs.io/en/v5/web3.eth.html#web3.eth.Eth.get_storage_at), etc.).
    
    </aside>
    
    An example of how it’s done using Foundry’s [forge](https://book.getfoundry.sh/forge/):
    
    ```solidity
    function getSsvSlot0() private view returns(bytes32 ssvSlot0) {
        bytes32 slot = bytes32(uint256(keccak256("ssv.network.storage.protocol")) - 1);
        ssvSlot0 = vm.load(ssvNetworkAddress, slot);
    }
    ```
    
    `slot` here equals to `0x0f1d85405047bdb6b0a60e27531f52a1f7a948613527b9b83a7552558207aa15`
    
    An example of how it’s done using Foundry’s [cast](https://book.getfoundry.sh/cast/) on Mainnet:
    
    ```bash
    cast storage 0xDD9BC35aE942eF0cFa76930954a156B3fF30a4E1 6836850959782774711213773224022472945316713988199727877409042202683022748181 --rpc-url https://rpc.ankr.com/eth
    ```
    

1. Client gets the latest SSV cluster state either from [SSV API](https://api.ssv.network/documentation) or from [SSV Scanner CLI](https://docs.ssv.network/validator-user-guides/tools/ssv-scanner-cli). (`P2pSsvProxy` ****instance address predicted in Step 7 is the cluster owner).
2. Client gets all the operator fees (per block) either from [SSV API](https://api.ssv.network/documentation) or from **SSVNetworkViews**’s `getOperatorFee` function.
3. Client gets all the network fee (per block) either from [SSV API](https://api.ssv.network/documentation) or from **SSVNetworkViews**’s `getNetworkFee` function.
4. Client gets all the liquidation threshold period (in blocks) either from [SSV API](https://api.ssv.network/documentation) or from **SSVNetworkViews**’s `getLiquidationThresholdPeriod` function.
5. Client calculates the SSV token amount required to serve all 100 validators for the desired period of time (in blocks). We recommend the desired period at least **250000** blocks (about 35 days).
    
    $tokenAmount = (sum(Operator Fees) + Network Fee) * (Liquidation Threshold Period + Desired Period) * 100$
    
6. Client calls `P2pSsvProxyFactory`'s `depositEthAndRegisterValidators` function with the data prepared above in batches of 50 validators. (For 100 validators, it’s going to be 2 transactions). The ETH value should be 1600 ETH (32 ETH * 50 validators) in each transaction.
    - `depositEthAndRegisterValidators` interface
        
        ```solidity
        function depositEthAndRegisterValidators(
            DepositData calldata _depositData,
            address _withdrawalCredentialsAddress,
        
            SsvPayload calldata _ssvPayload,
        
            FeeRecipient calldata _clientConfig,
            FeeRecipient calldata _referrerConfig
        ) external payable returns (address p2pSsvProxy);
        
        struct DepositData {
            bytes[] signatures;
            bytes32[] depositDataRoots;
        }
        
        struct SsvPayload {
            SsvOperator[] ssvOperators;
            SsvValidator[] ssvValidators;
            Cluster cluster;
            uint256 tokenAmount;
            bytes32 ssvSlot0;
        }
        
        struct SsvOperator {
            address owner;
            uint64 id;
            bytes32 snapshot;
            uint256 fee;
        }
        
        struct SsvValidator {
            bytes pubkey;
            bytes sharesData;
        }
        
        struct Cluster {
            uint32 validatorCount;
            uint64 networkFeeIndex;
            uint64 index;
            bool active;
            uint256 balance;
        }
        
        struct FeeRecipient {
            uint96 basisPoints;
            address payable recipient;
        }
        ```
        

### 3. [Deprecated] Without ETH deposit (with data generation on the client side)

> Client has 100 already deposited validators and wants to distribute the keys with DVT (SSV), preserving custody over withdrawal credentials and private keys of the validators.
> 

All the steps below can happen client-side without any interaction with P2P servers. SSV API can be used for convenience, although, all the data is also available on-chain.

1. Client reads a list of addresses of allowed SSV operator owners from **P2pSsvProxyFactory** contract’s `getAllowedSsvOperatorOwners` function. (For example, it can return 4 addresses).
2. Client reads allowed SSV operator IDs from **P2pSsvProxyFactory** contract’s `getAllowedSsvOperatorIds` function providing it with the address of the SSV operator owner from the previous step each time it’s called. (For example, for 4 addresses, `getAllowedSsvOperatorIds` function should be called 4 times. As a result, the client gets 4 SSV operator IDs).
3. Client predicts `**FeeDistributor**` instance address by reading **`FeeDistributorFactory`**’s `predictFeeDistributorAddress` function. 
    
    Need to provide it with:
    
    - `_referenceFeeDistributor` - address of the template `FeeDistributor` (can be of any type like `ElOnlyFeeDistributor`, `OracleFeeDistributor`, or `ContractWcFeeDistributor`)
    - `_clientConfig` (basis points, client fee recipient address)
    - `_referrerConfig`(basis points, referrer fee recipient address)
4. Client predicts `**P2pSsvProxy`** instance address by reading `**P2pSsvProxyFactory**`'s `predictP2pSsvProxyAddress` function, providing it with the `FeeDistributor` instance address from the previous step.
5. Client generates 100 SSV keyshares JSON files choosing operator IDs from Step 2 and cluster owner from Step 4. 
    
    (`P2pSsvProxy` ****instance address is the cluster owner).
    
    [ssv-keys](https://github.com/bloxapp/ssv-keys) tool can be used for generation.
    
6. Client reads operator snapshots from **SSVNetwork** contract’s storage slots. Each operator has its own snapshot.
    
    <aside>
    💡 This can be done using any library with RPC access to Ethereum execution layer blockchain (`eth_getStorageAt` ****RPC Method, e.g. [ethers.js](https://docs.ethers.org/v5/api/providers/provider/#Provider-getStorageAt), [web3.py](https://web3py.readthedocs.io/en/v5/web3.eth.html#web3.eth.Eth.get_storage_at), etc.).
    
    </aside>
    
    An example of how it’s done using Foundry’s [forge](https://book.getfoundry.sh/forge/):
    
    ```solidity
    function getSnapshot(uint64 operatorId) private view returns(bytes32 snapshot) {
        uint256 p = uint256(keccak256("ssv.network.storage.main")) + 5;
        bytes32 slot1 = bytes32(uint256(keccak256(abi.encode(uint256(operatorId), p))) + 2);
        snapshot = vm.load(ssvNetworkAddress, slot1);
    }
    ```
    
7. Client reads slot #`6836850959782774711213773224022472945316713988199727877409042202683022748181` (DEC) `0x0f1d85405047bdb6b0a60e27531f52a1f7a948613527b9b83a7552558207aa15` (HEX) from **SSVNetwork** contract’s storage.
    
    <aside>
    💡 This can be done using any library with RPC access to Ethereum execution layer blockchain (`eth_getStorageAt` ****RPC Method, e.g. [ethers.js](https://docs.ethers.org/v5/api/providers/provider/#Provider-getStorageAt), [web3.py](https://web3py.readthedocs.io/en/v5/web3.eth.html#web3.eth.Eth.get_storage_at), etc.).
    
    </aside>
    
    An example of how it’s done using Foundry’s [forge](https://book.getfoundry.sh/forge/):
    
    ```solidity
    function getSsvSlot0() private view returns(bytes32 ssvSlot0) {
        bytes32 slot = bytes32(uint256(keccak256("ssv.network.storage.protocol")) - 1);
        ssvSlot0 = vm.load(ssvNetworkAddress, slot);
    }
    ```
    
    `slot` here equals to `0x0f1d85405047bdb6b0a60e27531f52a1f7a948613527b9b83a7552558207aa15`
    
    An example of how it’s done using Foundry’s [cast](https://book.getfoundry.sh/cast/) on Mainnet:
    
    ```bash
    cast storage 0xDD9BC35aE942eF0cFa76930954a156B3fF30a4E1 6836850959782774711213773224022472945316713988199727877409042202683022748181 --rpc-url https://rpc.ankr.com/eth
    ```
    

1. Client gets the latest SSV cluster state either from [SSV API](https://api.ssv.network/documentation) or from [SSV Scanner CLI](https://docs.ssv.network/validator-user-guides/tools/ssv-scanner-cli). (`P2pSsvProxy` ****instance address predicted in Step 4 is the cluster owner).
2. Client gets all the operator fees (per block) either from [SSV API](https://api.ssv.network/documentation) or from **SSVNetworkViews**’s `getOperatorFee` function.
3. Client gets all the network fee (per block) either from [SSV API](https://api.ssv.network/documentation) or from **SSVNetworkViews**’s `getNetworkFee` function.
4. Client gets all the liquidation threshold period (in blocks) either from [SSV API](https://api.ssv.network/documentation) or from **SSVNetworkViews**’s `getLiquidationThresholdPeriod` function.
5. Client calculates the SSV token amount required to serve all 100 validators for the desired period of time (in blocks). We recommend the desired period at least **250000** blocks (about 35 days).
    
    $tokenAmount = (sum(Operator Fees) + Network Fee) * (Liquidation Threshold Period + Desired Period) * 100$
    
6. Client reads the ETH amount required to cover SSV token costs from `P2pSsvProxyFactory`'s `getNeededAmountOfEtherToCoverSsvFees` function providing it with the `tokenAmount` from the previous step.
7. Client calls `P2pSsvProxyFactory`'s `registerValidators` function with the data prepared above. The ETH value should be equal to the ETH amount required to cover SSV token costs (from the previous step).
    - `registerValidators` interface
        
        ```solidity
        function registerValidators(
            SsvPayload calldata _ssvPayload,
            FeeRecipient calldata _clientConfig,
            FeeRecipient calldata _referrerConfig
        ) external payable returns (address);
        
        struct SsvPayload {
            SsvOperator[] ssvOperators;
            SsvValidator[] ssvValidators;
            Cluster cluster;
            uint256 tokenAmount;
            bytes32 ssvSlot0;
        }
        
        struct SsvOperator {
            address owner;
            uint64 id;
            bytes32 snapshot;
            uint256 fee;
        }
        
        struct SsvValidator {
            bytes pubkey;
            bytes sharesData;
        }
        
        struct Cluster {
            uint32 validatorCount;
            uint64 networkFeeIndex;
            uint64 index;
            bool active;
            uint256 balance;
        }
        
        struct FeeRecipient {
            uint96 basisPoints;
            address payable recipient;
        }
        ```
        


## Asset recovery

Both `P2pSsvProxyFactory` and `P2pSsvProxy` contracts have built-in functions to recover (send to any chosen address) ETH and any ERC-20, ERC-721, and ERC-1155 tokens by the owner (P2P).

```solidity
function transferEther(address _recipient, uint256 _amount) external;
function transferERC20(address _token, address _recipient, uint256 _amount) external;
function transferERC721(address _token, address _recipient, uint256 _tokenId) external;
function transferERC1155(address _token, address _recipient, uint256 _tokenId, uint256 _amount, bytes calldata _data) external;
```

## Contracts

### **P2pSsvProxyFactory**

P2pSsvProxyFactory exists as a single instance for everyone. It is the entry point for validator registration.

- **UML Class Diagram**
    
    ![Untitled](P2P%20SSV%20Proxy%20contracts%20doc_img/factory_class.png)
    
- **Call Graph**
    
    ![Untitled](P2P%20SSV%20Proxy%20contracts%20doc_img/factory_calls.svg)
    

It stores:

- `referenceFeeDistributor` - a template set by P2P to be used for new `FeeDistributor` instances. Can be changed by P2P at any time. It will only affect the new clusters. Existing clusters will keep their existing `FeeDistributor` instance.
- `referenceP2pSsvProxy` - a template set by P2P to be used for new `P2pSsvProxy` instances. Can be changed by P2P at any time. It will only affect the new clusters. Existing clusters will keep their existing `P2pSsvProxy` instance.
- `allowedSsvOperatorOwners` - a set of addresses of SSV operator owners (both P2P and partners). Only P2P can add or remove addresses from the set.
- `allowedSsvOperatorIds` - a mapping of (operator owner address → SSV operator IDs list). The list of allowed SSV operator IDs for each address is limited to 24 IDs. The operator owner can update only their list. P2P can update lists of any owners.
- `allClientP2pSsvProxies` - a mapping of (client address → a list of addresses of the deployed client `P2pSsvProxy` instances). Updated automatically during `P2pSsvProxy` instance deployment.
- `allP2pSsvProxies` - a list of all ever deployed client `P2pSsvProxy` instances. Updated automatically during `P2pSsvProxy` instance deployment.
- `clientSelectors` - a mapping to check if a certain selector (function signature) is allowed for clients to call on `SSVNetwork` via `P2pSsvProxy`.
- `operatorSelectors` - a mapping to check if a certain selector (function signature) is allowed for a P2P operator to call on `SSVNetwork` via `P2pSsvProxy`.
- `ssvPerEthExchangeRateDividedByWei` - Exchange rate between SSV and ETH set by P2P. (*If 1 SSV = 0.007539 ETH, it should be 0.007539 * 10^18 = 7539000000000000*). Only used during validator registration without ETH deposits to cover SSV token costs with client ETH.

P2pSsvProxyFactory’s functions:

- `depositEthAndRegisterValidators` - batch validator registration with ETH deposit. Callable by anyone.
    - interface
        
        ```solidity
        function depositEthAndRegisterValidators(
            DepositData calldata _depositData,
            address _withdrawalCredentialsAddress,
        
            SsvPayload calldata _ssvPayload,
        
            FeeRecipient calldata _clientConfig,
            FeeRecipient calldata _referrerConfig
        ) external payable returns (address p2pSsvProxy);
        ```
        
- `registerValidators` - batch validator registration without ETH deposit. Callable by anyone.
    - interface
        
        ```solidity
        function registerValidators(
            SsvPayload calldata _ssvPayload,
            FeeRecipient calldata _clientConfig,
            FeeRecipient calldata _referrerConfig
        ) external payable returns (address);
        ```
        
- `predictP2pSsvProxyAddress` - get `P2pSsvProxy` instance address for a given `FeeDistributor` instance address.
    - interface
        
        ```solidity
        function predictP2pSsvProxyAddress(
            address _feeDistributorInstance
        ) external view returns (address);
        ```
        

- Mainnet: [0xcb924D4BE3Ff04B2d2116fE116138950373111d9](https://etherscan.io/address/0xcb924D4BE3Ff04B2d2116fE116138950373111d9)
- Holesky: [0xE9DfC1850110DadF68402Ec6AD2B9bDfB7980733](https://holesky.etherscan.io/address/0xE9DfC1850110DadF68402Ec6AD2B9bDfB7980733)

### **P2pSsvProxy**

P2pSsvProxy has identity tied to `FeeDistributor` *.* A new instance of `P2pSsvProxy` is created each time when the first SSV validator registration happens for a set of:

- `_referenceFeeDistributor` - address of the template `FeeDistributor`
- `_clientConfig` (basis points, client fee recipient address)
- `_referrerConfig`(basis points, referrer fee recipient address)

- **UML Class Diagram**
    
    ![Untitled](P2P%20SSV%20Proxy%20contracts%20doc_img/proxy_class.png)
    
- **Call Graph**
    
    ![Untitled](P2P%20SSV%20Proxy%20contracts%20doc_img/proxy_calls.svg)
    

It stores:

`feeDistributor` - *`FeeDistributor`* instance address

P2pSsvProxy allows to call all `SSVNetwork` functions having P2pSsvProxy instance as msg.sender for those calls.

For the client, only `removeValidator` function is available out of the box. It’s still possible for P2P to allow any other functions for clients to call. It’s done via P2pSsvProxyFactory’s `setAllowedSelectorsForClient` function.

- Mainnet: [0xec17A02B2A8b0C291C0DddE2a00Ca24477c17ED5](https://etherscan.io/address/0xec17A02B2A8b0C291C0DddE2a00Ca24477c17ED5)
- Holesky: [0x1e534b1B344fDA49F2778b9b956f7EeB2280e258](https://holesky.etherscan.io/address/0x1e534b1B344fDA49F2778b9b956f7EeB2280e258)

### **DepositContract**

Native ETH2 (Beacon) deposit contract, 1 for all.

- Mainnet: [0x00000000219ab540356cBB839Cbe05303d7705Fa](https://etherscan.io/address/0x00000000219ab540356cBB839Cbe05303d7705Fa)
- Holesky: [0x4242424242424242424242424242424242424242](https://holesky.etherscan.io/address/0x4242424242424242424242424242424242424242)

### FeeDistributorFactory

`FeeDistributorFactory` 1 for all. Predicts the address and creates FeeDistributor instances.

```solidity
function predictFeeDistributorAddress(
    address _referenceFeeDistributor,
    FeeRecipient calldata _clientConfig,
    FeeRecipient calldata _referrerConfig
) external view returns (address);
```

```solidity
function createFeeDistributor(
    address _referenceFeeDistributor,
    FeeRecipient calldata _clientConfig,
    FeeRecipient calldata _referrerConfig
) external returns (address newFeeDistributorAddress);
```

- Mainnet: [0x86a9f3e908b4658A1327952Eb1eC297a4212E1bb](https://etherscan.io/address/0x86a9f3e908b4658A1327952Eb1eC297a4212E1bb)
- Holesky: [0x5cdF046Bd49629E5130a4A82400733523Ba5820C](https://holesky.etherscan.io/address/0x5cdF046Bd49629E5130a4A82400733523Ba5820C)

### **FeeDistributor**

FeeDistributor is a family of contracts with the same interface. Currently, there are 3 types of  FeeDistributor:

- `ElOnlyFeeDistributor` accepting and splitting EL rewards only, WC == client rewards recipient address
- `OracleFeeDistributor` accepting EL rewards only but splitting them with consideration of CL rewards, WC == client rewards recipient address
- `ContractWcFeeDistributor` accepting and splitting both CL and EL rewards, WC == address of a client instance of `ContractWcFeeDistributor` contract

You can read more about them [here](https://www.notion.so/Autonomous-On-chain-ETH-Staking-0eeb5e3b76424d4da689ed4e96a4a8ec?pvs=21).

Also, for each type of `FeeDistributor` contract, there is a **reference instance** that doesn’t belong to any client and only exists as a template. The address of such a template can be passed to `FeeDistributorFactory`'s `predictFeeDistributorAddress` and `createFeeDistributor` functions.

**Reference (template) FeeDistributor instances:**

- Mainnet:
    - [OracleFeeDistributor](https://etherscan.io/address/0x7109deeb07aa9eed1e2613f88b2f3e1e6c05163f) 0x7109DeEb07aa9Eed1e2613F88b2f3E1e6C05163f
- Holesky:
    - [OracleFeeDistributor](https://holesky.etherscan.io/address/0x26766611723B654DeE5F041C8E20FDBC4EB37b31) 0x26766611723B654DeE5F041C8E20FDBC4EB37b31

For each set of 

- `_referenceFeeDistributor` - address of the reference `FeeDistributor`
- `_clientConfig` (basis points, client fee recipient address)
- `_referrerConfig`(basis points, referrer fee recipient address)

there will be a separate instance of `FeeDistributor`. Its address can be predicted even before it has been deployed using FeeDistributorFactory’s `predictFeeDistributorAddress` function.

The actual deployment is done using FeeDistributorFactory’s `createFeeDistributor` function.

### **SSV Token**

1 for all

ERC-20 token used for paying fees in SSV.

- Mainnet: [0x9D65fF81a3c488d585bBfb0Bfe3c7707c7917f54](https://etherscan.io/address/0x9D65fF81a3c488d585bBfb0Bfe3c7707c7917f54)
- Holesky: [0xad45A78180961079BFaeEe349704F411dfF947C6](https://holesky.etherscan.io/address/0xad45A78180961079BFaeEe349704F411dfF947C6)

### **SSVNetwork**

1 for all

[Read in SSV doc](https://docs.ssv.network/developers/smart-contracts/ssvnetwork)

- Mainnet: [0xDD9BC35aE942eF0cFa76930954a156B3fF30a4E1](https://etherscan.io/address/0xDD9BC35aE942eF0cFa76930954a156B3fF30a4E1)
- Holesky: [0x38A4794cCEd47d3baf7370CcC43B560D3a1beEFA](https://holesky.etherscan.io/address/0x38A4794cCEd47d3baf7370CcC43B560D3a1beEFA)

### **SSVNetworkViews**

1 for all

[Read in SSV doc](https://docs.ssv.network/developers/smart-contracts/ssvnetworkviews)

- Mainnet: [0xafE830B6Ee262ba11cce5F32fDCd760FFE6a66e4](https://etherscan.io/address/0xafE830B6Ee262ba11cce5F32fDCd760FFE6a66e4)
- Holesky: [0x352A18AEe90cdcd825d1E37d9939dCA86C00e281](https://holesky.etherscan.io/address/0x352A18AEe90cdcd825d1E37d9939dCA86C00e281)

## Links

[SSV Docs](https://docs.ssv.network/)

[SSV API](https://api.ssv.network/documentation/)
