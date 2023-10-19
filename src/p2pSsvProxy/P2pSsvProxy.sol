// SPDX-FileCopyrightText: 2023 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;

import "../@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

import "../constants/P2pConstants.sol";
import "../interfaces/ssv/ISSVNetwork.sol";
import "../access/OwnableWithOperator.sol";
import "../structs/P2pStructs.sol";
import "../interfaces/IDepositContract.sol";
import "../interfaces/IFeeDistributor.sol";
import "../interfaces/IFeeDistributorFactory.sol";

/// @notice _referenceFeeDistributor should implement IFeeDistributor interface
/// @param _passedAddress passed address for _referenceFeeDistributor
error P2pSsvProxy__NotFeeDistributor(address _passedAddress);

/// @notice Should be a FeeDistributorFactory contract
/// @param _passedAddress passed address that does not support IFeeDistributorFactory interface
error P2pSsvProxy__NotFactory(address _passedAddress);

contract P2pSsvProxy is OwnableWithOperator {
    ISSVNetwork public immutable i_ssvNetwork;
    IERC20 public immutable i_ssvToken;
    IDepositContract i_depositContract;
    IFeeDistributorFactory public immutable i_feeDistributorFactory;
    address public i_client;

    address public s_referenceFeeDistributor;
    uint64[] public s_operatorIds;

    constructor(address _feeDistributorFactory, address _client) {
        if (!ERC165Checker.supportsInterface(_feeDistributorFactory, type(IFeeDistributorFactory).interfaceId)) {
            revert P2pSsvProxy__NotFactory(_feeDistributorFactory);
        }

        i_feeDistributorFactory = IFeeDistributorFactory(_feeDistributorFactory);

        i_ssvNetwork = (block.chainid == 1)
            ? ISSVNetwork(0xDD9BC35aE942eF0cFa76930954a156B3fF30a4E1)
            : ISSVNetwork(0xC3CD9A0aE89Fff83b71b58b6512D43F8a41f363D);

        i_ssvToken = (block.chainid == 1)
            ? IERC20(0x9D65fF81a3c488d585bBfb0Bfe3c7707c7917f54)
            : IERC20(0x3a9f01091C446bdE031E39ea8354647AFef091E7);

        i_depositContract = (block.chainid == 1)
            ? IERC20(0x00000000219ab540356cBB839Cbe05303d7705Fa)
            : IERC20(0xff50ed3d0ec03aC01D4C79aAd74928BFF48a7b2b);

        i_client = _client;

        i_ssvToken.approve(address(i_ssvNetwork), type(uint256).max);
    }

    function setReferenceFeeDistributor(
        address _referenceFeeDistributor
    ) external onlyOperatorOrOwner {
        if (!ERC165Checker.supportsInterface(_referenceFeeDistributor, type(IFeeDistributor).interfaceId)) {
            revert P2pSsvProxy__NotFeeDistributor(_referenceFeeDistributor);
        }

        s_referenceFeeDistributor = _referenceFeeDistributor;
    }

    function registerValidators(
        SsvValidator[] calldata _ssvValidators,
        uint256 _tokenAmount,
        bytes32 _mevRelay,

        FeeRecipient calldata _clientConfig,
        FeeRecipient calldata _referrerConfig
    ) external {
        uint256 validatorCount = _ssvValidators.length;
        uint256 tokenPerValidator = _tokenAmount / validatorCount;
        address referenceFeeDistributor = s_referenceFeeDistributor;

        for (uint256 i = 0; i < validatorCount;) {
            // ETH deposit
            bytes memory withdrawalCredentials = abi.encodePacked(
                hex'010000000000000000000000',
                    _ssvValidators[i].depositData.withdrawalCredentialsAddress
            );
            i_depositContract.deposit(
                _ssvValidators[i].pubkey,
                withdrawalCredentials,
                _ssvValidators[i].depositData.signature,
                _ssvValidators[i].depositData.depositDataRoot
            );

            // createFeeDistributor
            address feeDistributorInstance = i_feeDistributorFactory.predictFeeDistributorAddress(
                referenceFeeDistributor,
                _clientConfig,
                _referrerConfig
            );
            if (feeDistributorInstance.code.length == 0) {
                // if feeDistributorInstance doesn't exist, deploy it
                i_feeDistributorFactory.createFeeDistributor(
                    referenceFeeDistributor,
                    _clientConfig,
                    _referrerConfig
                );
            }

            i_ssvNetwork.registerValidator(
                _ssvValidators[i].pubkey,
                    _operatorIds,
                    _sharesData[i],
                    tokenPerValidator,
                    _clusters[i]
            );

            unchecked {
                ++i;
            }
        }
    }

    function removeValidators(
        bytes[] calldata _pubkeys,
        uint64[] calldata _operatorIds,
        ISSVNetwork.Cluster[] calldata _clusters
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
        ISSVNetwork.Cluster[] calldata _clusters
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
        ISSVNetwork.Cluster[] calldata _clusters
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
        ISSVNetwork.Cluster[] calldata _clusters
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
        ISSVNetwork.Cluster[] calldata _clusters
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

    function setFeeRecipientAddress(
        address feeRecipientAddress
    ) external onlyOperatorOrOwner {
        i_ssvNetwork.setFeeRecipientAddress(feeRecipientAddress);
    }
}
