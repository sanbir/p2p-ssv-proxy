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
import "../structs/P2pStructs.sol";

error P2pSsvProxyFactory__NotAllowedSsvOperatorOwner(address _caller);

error P2pSsvProxyFactory__MaxAllowedSsvOperatorIdsExceeded();

error P2pSsvProxyFactory__OldAndNewCountsShouldMatch(uint256 oldCount, uint256 newCount);

error P2pSsvProxyFactory__TryingToReplaceMoreThanExist(uint256 countToReplace, uint256 existingCount);

contract P2pSsvProxyFactory is OwnableAssetRecoverer, OwnableWithOperator, ERC165, IP2pSsvProxyFactory {
    IDepositContract public immutable i_depositContract;
    IFeeDistributorFactory public immutable i_feeDistributorFactory;
    P2pSsvProxy public immutable i_referenceP2pSsvProxy;

    address public s_referenceFeeDistributor;
    mapping(address => bool) public s_allowedSsvOperatorOwners;
    mapping(address => uint64[]) public s_allowedSsvOperatorIds;

    modifier onlyOperatorOwner() {
        bool isAllowed = s_allowedSsvOperatorOwners[msg.sender];
        if (!isAllowed) {
            revert P2pSsvProxyFactory__NotAllowedSsvOperatorOwner(msg.sender);
        }
        _;
    }

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

    function setAllowedSsvOperatorOwners(
        address[] calldata _allowedSsvOperatorOwners
    ) external onlyOperatorOrOwner {
        uint256 count = _allowedSsvOperatorOwners.length;
        for (uint256 i = 0; i < count;) {
            s_allowedSsvOperatorOwners[_allowedSsvOperatorOwners[i]] = true;

            unchecked {
                ++i;
            }
        }
    }

    function removeAllowedSsvOperatorOwners(
        address[] calldata _allowedSsvOperatorOwnersToRemove
    ) external onlyOperatorOrOwner {
        uint256 count = _allowedSsvOperatorOwnersToRemove.length;
        for (uint256 i = 0; i < count;) {
            delete s_allowedSsvOperatorOwners[_allowedSsvOperatorOwnersToRemove[i]];
            delete s_allowedSsvOperatorIds[_allowedSsvOperatorOwnersToRemove[i]];

            unchecked {
                ++i;
            }
        }
    }

    function addSsvOperatorIds(
        uint64[] calldata _operatorIds
    ) external onlyOperatorOwner {
        uint256 count = _operatorIds.length;
        uint64[] storage allowedForSender = s_allowedSsvOperatorIds[msg.sender];

        if (count + allowedForSender.length >= MAX_ALLOWED_SSV_OPERATOR_IDS) {
            revert P2pSsvProxyFactory__MaxAllowedSsvOperatorIdsExceeded();
        }

        for (uint256 i = 0; i < count;) {
            allowedForSender.push(_operatorIds[i]);

            unchecked {
                ++i;
            }
        }
    }

    function clearSsvOperatorIds() external onlyOperatorOwner {
        delete s_allowedSsvOperatorIds[msg.sender];
    }

    function replaceSsvOperatorIds(
        uint64[] calldata _operatorIdsToReplace,
        uint64[] calldata _newOperatorIds
    ) external onlyOperatorOwner {
        uint256 countToReplace = _operatorIdsToReplace.length;
        uint256 countNew = _newOperatorIds.length;

        if (countToReplace != countNew) {
            revert P2pSsvProxyFactory__OldAndNewCountsShouldMatch(countToReplace, countNew);
        }

        uint64[] storage existingIds = s_allowedSsvOperatorIds[msg.sender];
        uint256 existingCount = existingIds.length;

        if (countToReplace > existingCount) {
            revert P2pSsvProxyFactory__TryingToReplaceMoreThanExist(countToReplace, existingCount);
        }

        uint256 alreadyReplaced;
        for (uint256 i = 0; i < existingCount;) {
            uint64 existingId = existingIds[i];

            for (uint256 j = 0; j < countToReplace;) {
                if (_operatorIdsToReplace[j] == existingId) {
                    existingIds[i] = _newOperatorIds[j];
                    ++alreadyReplaced;
                    break;
                }

                unchecked {
                    ++j;
                }
            }

            if (alreadyReplaced == countToReplace) {
                break;
            }

            unchecked {
                ++i;
            }
        }
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
