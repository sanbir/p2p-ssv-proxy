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
        IERC20 ssvToken = IERC20(vm.envAddress("SSV_TOKEN"));

        address feeDistributorFactory = vm.envAddress("FEE_DISTRIBUTOR_FACTORY");
        address referenceFeeDistributor = vm.envAddress("REFERENCE_FEE_DISTRIBUTOR");

        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerKey);

        P2pSsvProxyFactory p2pSsvProxyFactory = new P2pSsvProxyFactory(feeDistributorFactory, referenceFeeDistributor);
        P2pSsvProxy referenceP2pSsvProxy = new P2pSsvProxy(address(p2pSsvProxyFactory));
        p2pSsvProxyFactory.setReferenceP2pSsvProxy(address(referenceP2pSsvProxy));

        ssvToken.transfer(address(p2pSsvProxyFactory), 50 ether);

        address[] memory allowedSsvOperatorOwners = new address[](1);
        allowedSsvOperatorOwners[0] = vm.envAddress("ALLOWED_OPERATOR_OWNER");
        p2pSsvProxyFactory.setAllowedSsvOperatorOwners(allowedSsvOperatorOwners);

        IChangeOperator(address(feeDistributorFactory)).changeOperator(address(p2pSsvProxyFactory));

        uint64[8] memory operatorIds = [
            uint64(vm.envUint("OPERATOR_ID_1")),
            uint64(vm.envUint("OPERATOR_ID_2")),
            uint64(vm.envUint("OPERATOR_ID_3")),
            uint64(vm.envUint("OPERATOR_ID_4")),

            uint64(vm.envUint("OPERATOR_ID_5")),
            uint64(vm.envUint("OPERATOR_ID_6")),
            uint64(vm.envUint("OPERATOR_ID_7")),
            uint64(vm.envUint("OPERATOR_ID_8"))
        ];
        p2pSsvProxyFactory.setSsvOperatorIds(operatorIds, allowedSsvOperatorOwners[0]);

        p2pSsvProxyFactory.setSsvPerEthExchangeRateDividedByWei(vm.envUint("EXCHANGE_RATE"));

        p2pSsvProxyFactory.changeOperator(vm.envAddress("FACTORY_OPERATOR"));

        vm.stopBroadcast();

        return (
            p2pSsvProxyFactory,
            referenceP2pSsvProxy
        );
    }
}
