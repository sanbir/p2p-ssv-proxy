// SPDX-FileCopyrightText: 2023 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;

import "./constants/P2pConstants.sol";
import "./interfaces/ssv/ISSVClusters.sol";
import "./@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./access/OwnableWithOperator.sol";

/// @notice amount of parameters do no match
error P2pSsvProxy__AmountOfParametersError();

contract P2pSsvProxy is OwnableWithOperator {
    ISSVClusters public immutable i_ssvNetwork;
    IERC20 public immutable i_ssvToken;

    constructor() {
        i_ssvNetwork = (block.chainid == 1)
            ? ISSVClusters(0xDD9BC35aE942eF0cFa76930954a156B3fF30a4E1)
            : ISSVClusters(0xC3CD9A0aE89Fff83b71b58b6512D43F8a41f363D);

        i_ssvToken = (block.chainid == 1)
            ? IERC20(0x9D65fF81a3c488d585bBfb0Bfe3c7707c7917f54)
            : IERC20(0x3a9f01091C446bdE031E39ea8354647AFef091E7);

        i_ssvToken.approve(address(i_ssvNetwork), type(uint256).max);
    }

    function registerValidators(
        uint256 _tokenAmount,
        bytes[] calldata _pubkeys,
        uint64[] calldata _operatorIds,
        bytes[] calldata _sharesData,
        ISSVClusters.Cluster[] calldata _clusters
    ) external onlyOperatorOrOwner {
        uint256 validatorCount = _pubkeys.length;

        if (!(
            _sharesData.length == validatorCount &&
            _clusters.length == validatorCount
        )) {
            revert P2pSsvProxy__AmountOfParametersError();
        }

        uint256 tokenPerValidator = _tokenAmount / _pubkeys.length;

        for (uint256 i = 0; i < validatorCount;) {
            i_ssvNetwork.registerValidator(_pubkeys[i], _operatorIds, _sharesData[i], tokenPerValidator, _clusters[i]);

            unchecked {
                ++i;
            }
        }
    }

    function removeValidators(
        bytes[] calldata _pubkeys,
        uint64[] calldata _operatorIds,
        ISSVClusters.Cluster[] calldata _clusters
    ) external onlyOperatorOrOwner {
        uint256 validatorCount = _pubkeys.length;

        if (!(
            _clusters.length == validatorCount
        )) {
            revert P2pSsvProxy__AmountOfParametersError();
        }

        for (uint256 i = 0; i < validatorCount;) {
            i_ssvNetwork.removeValidator(_pubkeys[i], _operatorIds, _clusters[i]);

            unchecked {
                ++i;
            }
        }
    }

    function liquidate(
        uint64[] calldata _operatorIds,
        ISSVClusters.Cluster[] calldata _clusters
    ) external onlyOperatorOrOwner {
        address clusterOwner = address(this);
        uint256 validatorCount = _clusters.length;

        for (uint256 i = 0; i < validatorCount;) {
            i_ssvNetwork.liquidate(clusterOwner, _operatorIds, _clusters[i]);

            unchecked {
                ++i;
            }
        }
    }

    function reactivate(
        uint256 _tokenAmount,
        uint64[] calldata _operatorIds,
        ISSVClusters.Cluster[] calldata _clusters
    ) external onlyOperatorOrOwner {
        uint256 tokenPerValidator = _tokenAmount / _clusters.length;
        uint256 validatorCount = _clusters.length;

        for (uint256 i = 0; i < validatorCount;) {
            i_ssvNetwork.reactivate(_operatorIds, tokenPerValidator, _clusters[i]);

            unchecked {
                ++i;
            }
        }
    }

    function depositToSSV(
        uint256 _tokenAmount,
        uint64[] calldata _operatorIds,
        ISSVClusters.Cluster[] calldata _clusters
    ) external onlyOperatorOrOwner {
        address clusterOwner = address(this);
        uint256 tokenPerValidator = _tokenAmount / _clusters.length;
        uint256 validatorCount = _clusters.length;

        for (uint256 i = 0; i < validatorCount;) {
            i_ssvNetwork.deposit(clusterOwner, _operatorIds, tokenPerValidator, _clusters[i]);

            unchecked {
                ++i;
            }
        }
    }

    function withdrawFromSSV(
        uint256 _tokenAmount,
        uint64[] calldata _operatorIds,
        ISSVClusters.Cluster[] calldata _clusters
    ) external onlyOperatorOrOwner {
        uint256 tokenPerValidator = _tokenAmount / _clusters.length;
        uint256 validatorCount = _clusters.length;

        for (uint256 i = 0; i < validatorCount;) {
            i_ssvNetwork.withdraw(_operatorIds, tokenPerValidator, _clusters[i]);

            unchecked {
                ++i;
            }
        }
    }

    function withdrawSSVTokens(
        address _to,
        uint256 _amount
    ) external onlyOwner {
        i_ssvToken.transfer(_to, _amount);
    }
}
