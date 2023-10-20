// SPDX-FileCopyrightText: 2023 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;

import "./IP2pSsvProxyFactory.sol";
import "../assetRecovering/OwnableAssetRecoverer.sol";
import "../access/OwnableWithOperator.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../structs/P2pStructs.sol";
import "../interfaces/IDepositContract.sol";
import "../interfaces/p2p/IFeeDistributor.sol";
import "../interfaces/p2p/IFeeDistributorFactory.sol";
import "../p2pSsvProxy/P2pSsvProxy.sol";

contract P2pSsvProxyFactory is OwnableAssetRecoverer, OwnableWithOperator, ERC165, IP2pSsvProxyFactory {
    IDepositContract public immutable i_depositContract;
    IFeeDistributorFactory public immutable i_feeDistributorFactory;
    P2pSsvProxy public immutable i_referenceP2pSsvProxy;

    address public s_referenceFeeDistributor;
    mapping(address => bool) public s_allowedSsvOperators;
    mapping(address => uint64[]) public s_allowedSsvOperatorIds;

    constructor(
        address _feeDistributorFactory,
        address _referenceFeeDistributor
    ) {
        if (!ERC165Checker.supportsInterface(_feeDistributorFactory, type(IFeeDistributorFactory).interfaceId)) {
            revert P2pSsvProxy__NotFeeDistributorFactory(_feeDistributorFactory);
        }
        i_feeDistributorFactory = IFeeDistributorFactory(_feeDistributorFactory);

        if (!ERC165Checker.supportsInterface(_referenceFeeDistributor, type(IFeeDistributor).interfaceId)) {
            revert P2pSsvProxy__NotFeeDistributor(_referenceFeeDistributor);
        }
        s_referenceFeeDistributor = _referenceFeeDistributor;

        i_depositContract = (block.chainid == 1)
            ? IERC20(0x00000000219ab540356cBB839Cbe05303d7705Fa)
            : IERC20(0xff50ed3d0ec03aC01D4C79aAd74928BFF48a7b2b);

        i_referenceP2pSsvProxy = new P2pSsvProxy(address(this));
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
}
