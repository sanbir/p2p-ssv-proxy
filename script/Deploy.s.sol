// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import {Script} from "forge-std/Script.sol";
import "../src/p2pSsvProxyFactory/P2pSsvProxyFactory.sol";
import "../src/mocks/IChangeOperator.sol";

contract Deploy is Script {

    function run() external {
        address p2pOrgUnlimitedEthDepositor = vm.envAddress("P2P_ORG_UNLIMITED_ETH_DEPOSITOR");
        address feeDistributorFactory = vm.envAddress("FEE_DISTRIBUTOR_FACTORY");
        address referenceFeeDistributor = vm.envAddress("REFERENCE_FEE_DISTRIBUTOR");

        address[] memory ssvOperatorOwners = new address[](4);
        ssvOperatorOwners[0] = 0xfeC26f2bC35420b4fcA1203EcDf689a6e2310363;
        ssvOperatorOwners[1] = 0x95b3D923060b7E6444d7C3F0FCb01e6F37F4c418;
        ssvOperatorOwners[2] = 0x47659cc5fB8CDC58bD68fEB8C78A8e19549d39C5;
        ssvOperatorOwners[3] = 0x9a792B1588882780Bed412796337E0909e51fAB7;

        P2pSsvProxyFactory p2pSsvProxyFactory = P2pSsvProxyFactory(0x1f72FC2585D283DfEcF748cc5d19c014158A7C6f);


        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerKey);


        p2pSsvProxyFactory.setAllowedSsvOperatorOwners(ssvOperatorOwners);

        p2pSsvProxyFactory.setSsvOperatorIds([uint64(59),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], ssvOperatorOwners[0]);
        p2pSsvProxyFactory.setSsvOperatorIds([uint64(52),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], ssvOperatorOwners[1]);
        p2pSsvProxyFactory.setSsvOperatorIds([uint64(55),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], ssvOperatorOwners[2]);
        p2pSsvProxyFactory.setSsvOperatorIds([uint64(57),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], ssvOperatorOwners[3]);

        vm.stopBroadcast();
    }
}
