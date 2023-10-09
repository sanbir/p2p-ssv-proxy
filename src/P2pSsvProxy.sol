// SPDX-FileCopyrightText: 2023 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;

import "./interfaces/IDepositContract.sol";
import "./constants/P2pConstants.sol";
import "./interfaces/ssv/ISSVClusters.sol";

contract P2pSsvProxy {
    IDepositContract public immutable i_depositContract;

    ISSVClusters public immutable i_ssvNetwork;

    uint64 public immutable i_operatorId1;
    uint64 public immutable i_operatorId2;
    uint64 public immutable i_operatorId3;
    uint64 public immutable i_operatorId4;

    constructor(uint64[4] memory _operatorIds) {
        i_depositContract = (block.chainid == 1) // Mainnet
            ? IDepositContract(0x00000000219ab540356cBB839Cbe05303d7705Fa)
            : (block.chainid == 5) // Goerli
                ? IDepositContract(0xff50ed3d0ec03aC01D4C79aAd74928BFF48a7b2b)
                : IDepositContract(0x4242424242424242424242424242424242424242); // Holesky

        i_ssvNetwork = (block.chainid == 1)
            ? ISSVClusters(0xDD9BC35aE942eF0cFa76930954a156B3fF30a4E1)
            : (block.chainid == 5)
                ? ISSVClusters(0xC3CD9A0aE89Fff83b71b58b6512D43F8a41f363D)
                : ISSVClusters(address(0)); // TODO Holesky

        i_operatorId1 = _operatorIds[0];
        i_operatorId2 = _operatorIds[1];
        i_operatorId3 = _operatorIds[2];
        i_operatorId4 = _operatorIds[3];
    }

    function getOperatorIds() private view returns(uint64[] memory) {
        uint64[] memory operatorIds = new uint64[](4);
        operatorIds[0] = i_operatorId1;
        operatorIds[1] = i_operatorId2;
        operatorIds[2] = i_operatorId3;
        operatorIds[3] = i_operatorId4;

        return operatorIds;
    }

    function depositAndRegisterOneValidator() private {
        i_depositContract.deposit{value : COLLATERAL}(
            _pubkeys[i],
            withdrawalCredentials,
            _signatures[i],
            _depositDataRoots[i]
        );

        i_ssvNetwork.registerValidator(_pubkeys[i], operatorIds, sharesData[i], tokenPerValidator, cluster[i]);
    }

    function deposit(
        uint256 _tokenAmount,
        address _eth2WithdrawalCredentialsAddress,
        bytes[] calldata _pubkeys,
        bytes[] calldata _signatures,
        bytes32[] calldata _depositDataRoots,
        bytes[] calldata sharesData,
        ISSVClusters.Cluster[] calldata cluster
    ) external payable {
        bytes memory withdrawalCredentials = abi.encodePacked(
            hex'010000000000000000000000',
            _eth2WithdrawalCredentialsAddress
        );

        uint64[] memory operatorIds = getOperatorIds();

        uint256 tokenPerValidator = _tokenAmount / _pubkeys.length;
//
//        for (uint256 i = 0; i < validatorCount;) {
//            i_depositContract.deposit{value : COLLATERAL}(
//                _pubkeys[i],
//                withdrawalCredentials,
//                _signatures[i],
//                _depositDataRoots[i]
//            );
//
//            i_ssvNetwork.registerValidator(_pubkeys[i], operatorIds, sharesData[i], tokenPerValidator, cluster[i]);
//
//            unchecked {
//                ++i;
//            }
//        }
    }
}
