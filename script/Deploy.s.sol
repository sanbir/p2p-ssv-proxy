// SPDX-FileCopyrightText: 2023 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;

import {Script} from "forge-std/Script.sol";
import "../src/p2pSsvProxyFactory/P2pSsvProxyFactory.sol";

contract Deploy is Script {

    function run() external returns (
        P2pSsvProxyFactory,
        P2pSsvProxy
    ) {
        address feeDistributorFactory = vm.envAddress("FEE_DISTRIBUTOR_FACTORY");
        address referenceFeeDistributor = vm.envAddress("REFERENCE_FEE_DISTRIBUTOR");

        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerKey);

        P2pSsvProxyFactory p2pSsvProxyFactory = new P2pSsvProxyFactory(feeDistributorFactory, referenceFeeDistributor);
        P2pSsvProxy referenceP2pSsvProxy = new P2pSsvProxy(address(p2pSsvProxyFactory));
        p2pSsvProxyFactory.setReferenceP2pSsvProxy(address(referenceP2pSsvProxy));

        vm.stopBroadcast();

        return (
            p2pSsvProxyFactory,
            referenceP2pSsvProxy
        );
    }
}
