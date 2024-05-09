// SPDX-FileCopyrightText: 2023 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;

import {Script} from "forge-std/Script.sol";
import "../src/p2pSsvProxyFactory/P2pSsvProxyFactory.sol";
import "../src/mocks/IChangeOperator.sol";

contract Deploy is Script {

    function run() external returns (
        P2pSsvProxyFactory,
        P2pSsvProxy
    ) {
        IERC20 ssvToken = IERC20(0xad45A78180961079BFaeEe349704F411dfF947C6);

        address feeDistributorFactory = 0x146847fA6Bee2b1b883dD2BD01B7242E7D6cfb8e;
        address referenceFeeDistributor = 0xE4CdD87ea30B2Bea11067d4dcA4cDFC07819cA35;

        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerKey);

        P2pSsvProxyFactory p2pSsvProxyFactory = new P2pSsvProxyFactory(feeDistributorFactory, referenceFeeDistributor);
        P2pSsvProxy referenceP2pSsvProxy = new P2pSsvProxy(address(p2pSsvProxyFactory));
        p2pSsvProxyFactory.setReferenceP2pSsvProxy(address(referenceP2pSsvProxy));

        ssvToken.transfer(address(p2pSsvProxyFactory), 50 ether);

        address[] memory allowedSsvOperatorOwners = new address[](4);
        allowedSsvOperatorOwners[0] = address(0x7bb11BE268088B000eD4B1b94014D40371A3a7d3);
        allowedSsvOperatorOwners[1] = address(0x382f6FF5B9a29FcF1Dd2bf8B86C3234Dc7ed2Df6);
        allowedSsvOperatorOwners[2] = address(0x262B0b1Dca4998BF8dbdF83b0cf63C2dC1d74F33);
        allowedSsvOperatorOwners[3] = address(0xE5Bb5322A34e831a77bF06a25D13a0bE9B0b9B30);
        p2pSsvProxyFactory.setAllowedSsvOperatorOwners(allowedSsvOperatorOwners);

        IChangeOperator(address(feeDistributorFactory)).changeOperator(address(p2pSsvProxyFactory));

        p2pSsvProxyFactory.setSsvOperatorIds([uint64(326), 315, 0,0,0,0,0,0], allowedSsvOperatorOwners[0]);
        p2pSsvProxyFactory.setSsvOperatorIds([uint64(236), 0,0,0,0,0,0,0], allowedSsvOperatorOwners[1]);
        p2pSsvProxyFactory.setSsvOperatorIds([uint64(306), 0,0,0,0,0,0,0], allowedSsvOperatorOwners[2]);
        p2pSsvProxyFactory.setSsvOperatorIds([uint64(400), 0,0,0,0,0,0,0], allowedSsvOperatorOwners[3]);

        p2pSsvProxyFactory.setSsvPerEthExchangeRateDividedByWei(uint112(vm.envUint("EXCHANGE_RATE")));
        p2pSsvProxyFactory.setMaxSsvTokenAmountPerValidator(uint112(vm.envUint("MAX_SSV_TOKEN_AMOUNT_PER_VALIDATOR")));

        p2pSsvProxyFactory.changeOperator(vm.envAddress("FACTORY_OPERATOR"));

        p2pSsvProxyFactory.transferOwnership(0x9aB843F2d60be2316F42B9764e98b532908AaB37);

        vm.stopBroadcast();

        return (
            p2pSsvProxyFactory,
            referenceP2pSsvProxy
        );
    }
}
