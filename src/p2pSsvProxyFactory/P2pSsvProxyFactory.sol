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
import "../@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "../@openzeppelin/contracts/proxy/Clones.sol";

error P2pSsvProxyFactory__NotFeeDistributor(address _passedAddress);

error P2pSsvProxyFactory__NotAllowedSsvOperatorOwner(address _caller);

error P2pSsvProxyFactory__MaxAllowedSsvOperatorIdsExceeded();

error P2pSsvProxyFactory__OldAndNewCountsShouldMatch(uint256 oldCount, uint256 newCount);

error P2pSsvProxyFactory__TryingToReplaceMoreThanExist(uint256 countToReplace, uint256 existingCount);

error P2pSsvProxyFactory__SsvOperatorOwnerAlreadyExists(address _ssvOperatorOwner);

error P2pSsvProxyFactory__SsvOperatorOwnerDoesNotExist(address _ssvOperatorOwner);

error P2pSsvProxyFactory__SsvOperatorNotAllowed(address _ssvOperatorOwner, uint64 _ssvOperatorId);

contract P2pSsvProxyFactory is OwnableAssetRecoverer, OwnableWithOperator, ERC165, IP2pSsvProxyFactory {
    using EnumerableSet for EnumerableSet.AddressSet;

    IDepositContract public immutable i_depositContract;
    IFeeDistributorFactory public immutable i_feeDistributorFactory;
    P2pSsvProxy public immutable i_referenceP2pSsvProxy;

    address public s_referenceFeeDistributor;
    EnumerableSet.AddressSet private s_allowedSsvOperatorOwners;
    mapping(address => uint64[8]) public s_allowedSsvOperatorIds;

    /// @notice client address -> array of client P2pSsvProxies mapping
    mapping(address => address[]) private s_allClientP2pSsvProxies;

    /// @notice array of all P2pSsvProxies for all clients
    address[] private s_allP2pSsvProxies;

    modifier onlySsvOperatorOwner() {
        bool isAllowed = s_allowedSsvOperatorOwners.contains(msg.sender);
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
            revert P2pSsvProxyFactory__NotFeeDistributor(_referenceFeeDistributor);
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
            revert P2pSsvProxyFactory__NotFeeDistributor(_referenceFeeDistributor);
        }

        s_referenceFeeDistributor = _referenceFeeDistributor;
    }

    function setAllowedSsvOperatorOwners(
        address[] calldata _allowedSsvOperatorOwners
    ) external onlyOperatorOrOwner {
        uint256 count = _allowedSsvOperatorOwners.length;
        for (uint256 i = 0; i < count;) {
            if (!s_allowedSsvOperatorOwners.add(_allowedSsvOperatorOwners[i])) {
                revert P2pSsvProxyFactory__SsvOperatorOwnerAlreadyExists(_allowedSsvOperatorOwners[i]);
            }

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
            if (!s_allowedSsvOperatorOwners.remove(_allowedSsvOperatorOwnersToRemove[i])) {
                revert P2pSsvProxyFactory__SsvOperatorOwnerDoesNotExist(_allowedSsvOperatorOwnersToRemove[i]);
            }

            unchecked {
                ++i;
            }
        }
    }

    function addSsvOperatorIds(
        uint64[] calldata _operatorIds
    ) external onlySsvOperatorOwner {
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

    function clearSsvOperatorIds() external onlySsvOperatorOwner {
        delete s_allowedSsvOperatorIds[msg.sender];
    }

    function replaceSsvOperatorIds(
        uint64[] calldata _operatorIdsToReplace,
        uint64[] calldata _newOperatorIds
    ) external onlySsvOperatorOwner {
        // TODO: check that _newOperatorIds are unique within s_allowedSsvOperatorIds

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

    function checkOperators(SsvOperator[] calldata _operators) private {
        uint256 operatorCount = _operators.length;
        for (uint256 i = 0; i < operatorCount;) {
            uint64[] memory allowedIds = s_allowedSsvOperatorIds[_operators[i].owner];

            bool isAllowed;
            for (uint256 j = 0; j < 8;) {
                if (allowedIds[j] == _operators[i].id) {
                    isAllowed = true;
                    break;
                }

                unchecked {
                    ++j;
                }
            }
            if (!isAllowed) {
                revert P2pSsvProxyFactory__SsvOperatorNotAllowed(_operators[i].owner, _operators[i].id);
            }
            isAllowed = false;

            unchecked {
                ++i;
            }
        }
    }

    function _makeBeaconDeposits(
        SsvValidator[] calldata _ssvValidators,
        address withdrawalCredentialsAddress
    ) private {
        uint256 validatorCount = _ssvValidators.length;

        for (uint256 i = 0; i < validatorCount;) {
            // ETH deposit
            bytes memory withdrawalCredentials = abi.encodePacked(
                hex'010000000000000000000000',
                withdrawalCredentialsAddress
            );
            i_depositContract.deposit(
                _ssvValidators[i].pubkey,
                withdrawalCredentials,
                _ssvValidators[i].depositData.signature,
                _ssvValidators[i].depositData.depositDataRoot
            );

            unchecked {
                ++i;
            }
        }
    }

    function predictP2pSsvProxyAddress(
        address _feeDistributorInstance
    ) public view returns (address) {
        return Clones.predictDeterministicAddress(
            address(i_referenceP2pSsvProxy),
            bytes32(_feeDistributorInstance)
        );
    }

    function createP2pSsvProxy(
        address _feeDistributorInstance
    ) external onlyOperatorOrOwner returns(address p2pSsvProxyInstance) {
        p2pSsvProxyInstance = _createP2pSsvProxy(_feeDistributorInstance);
    }

    function _createP2pSsvProxy(
        address _feeDistributorInstance
    ) private returns(address p2pSsvProxyInstance) {
        p2pSsvProxyInstance = predictP2pSsvProxyAddress(_feeDistributorInstance);
        if (p2pSsvProxyInstance.code.length == 0) { // if p2pSsvProxyInstance doesn't exist, deploy it
            if (!ERC165Checker.supportsInterface(_feeDistributorInstance, type(IFeeDistributor).interfaceId)) {
                revert P2pSsvProxyFactory__NotFeeDistributor(_feeDistributorInstance);
            }

            // clone the reference implementation of P2pSsvProxy
            p2pSsvProxyInstance = Clones.cloneDeterministic(
                address(i_referenceP2pSsvProxy),
                bytes32(_feeDistributorInstance)
            );

            // set the client address to the cloned P2pSsvProxy instance
            P2pSsvProxy(p2pSsvProxyInstance).initialize(_feeDistributorInstance);

            address client = IFeeDistributor(_feeDistributorInstance).client();

            // append new P2pSsvProxy address to all client P2pSsvProxies array
            s_allClientP2pSsvProxies[client].push(p2pSsvProxyInstance);

            // append new P2pSsvProxy address to all P2pSsvProxies array
            s_allP2pSsvProxies.push(p2pSsvProxyInstance);

            // emit event with the address of the newly created instance for the external listener
            emit P2pSsvProxyFactory__P2pSsvProxyCreated(
                p2pSsvProxyInstance,
                client,
                _feeDistributorInstance
            );
        }
    }

    function _createFeeDistributor(
        FeeRecipient calldata _clientConfig,
        FeeRecipient calldata _referrerConfig
    ) private returns(address feeDistributorInstance) {
        address referenceFeeDistributor = s_referenceFeeDistributor;

        feeDistributorInstance = i_feeDistributorFactory.predictFeeDistributorAddress(
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
    }

    function depositEthAndRegisterValidators(
        SsvOperator[] calldata _operators,
        SsvValidator[] calldata _ssvValidators,

        address _withdrawalCredentialsAddress,
        uint256 _tokenAmount,
        bytes32 _mevRelay,

        FeeRecipient calldata _clientConfig,
        FeeRecipient calldata _referrerConfig
    ) external payable {
        checkOperators(_operators);
        _makeBeaconDeposits(_ssvValidators, _withdrawalCredentialsAddress);

        address feeDistributorInstance = _createFeeDistributor(_clientConfig, _referrerConfig);
        address proxy = _createP2pSsvProxy(feeDistributorInstance);

        P2pSsvProxy(proxy).registerValidators(
            _ssvValidators,
            feeDistributorInstance,
            _tokenAmount
        );

        emit P2pSsvProxyFactory__RegistrationCompleted(proxy, _mevRelay);
    }
}
