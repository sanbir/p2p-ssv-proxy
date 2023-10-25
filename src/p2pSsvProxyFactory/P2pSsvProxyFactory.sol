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

error P2pSsvProxyFactory__DuplicateIdsNotAllowed();

error P2pSsvProxyFactory__ZeroOperatorIds();

contract P2pSsvProxyFactory is OwnableAssetRecoverer, OwnableWithOperator, ERC165, IP2pSsvProxyFactory {
    using EnumerableSet for EnumerableSet.AddressSet;

    IDepositContract public immutable i_depositContract;
    IFeeDistributorFactory public immutable i_feeDistributorFactory;
    P2pSsvProxy public immutable i_referenceP2pSsvProxy;

    address public s_referenceFeeDistributor;
    EnumerableSet.AddressSet private s_allowedSsvOperatorOwners;
    mapping(address => uint64[MAX_ALLOWED_SSV_OPERATOR_IDS]) public s_allowedSsvOperatorIds;

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
            ? IDepositContract(0x00000000219ab540356cBB839Cbe05303d7705Fa)
            : IDepositContract(0xff50ed3d0ec03aC01D4C79aAd74928BFF48a7b2b);

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

    function setSsvOperatorIds(
        uint64[MAX_ALLOWED_SSV_OPERATOR_IDS] calldata _operatorIds
    ) external onlySsvOperatorOwner {
        for (uint i = 0; i < _operatorIds.length;) {
            if (_operatorIds[i] == 0) {
                revert P2pSsvProxyFactory__ZeroOperatorIds();
            }

            for (uint j = i + 1; j < _operatorIds.length;) {
                if (_operatorIds[i] == _operatorIds[j]) {
                    revert P2pSsvProxyFactory__DuplicateIdsNotAllowed();
                }
                unchecked {
                    ++j;
                }
            }
            unchecked {
                ++i;
            }
        }

        s_allowedSsvOperatorIds[msg.sender] = _operatorIds;
    }

    function clearSsvOperatorIds() external onlySsvOperatorOwner {
        delete s_allowedSsvOperatorIds[msg.sender];
    }

    function checkOperators(SsvOperator[] calldata _operators) private view {
        uint256 operatorCount = _operators.length;
        for (uint256 i = 0; i < operatorCount;) {
            uint64[MAX_ALLOWED_SSV_OPERATOR_IDS] memory allowedIds = s_allowedSsvOperatorIds[_operators[i].owner];

            bool isAllowed;
            for (uint256 j = 0; j < MAX_ALLOWED_SSV_OPERATOR_IDS;) {
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
            bytes32(bytes20(_feeDistributorInstance))
        );
    }

    function createP2pSsvProxy(
        address _feeDistributorInstance
    ) external onlyOperatorOrOwner returns(address p2pSsvProxyInstance) {
        p2pSsvProxyInstance = _createP2pSsvProxy(_feeDistributorInstance);
    }

    function depositEthAndRegisterValidators(
        SsvOperator[] calldata _ssvOperators,
        SsvValidator[] calldata _ssvValidators,
        ISSVNetwork.Cluster calldata _cluster,
        uint256 _tokenAmount,

        address _withdrawalCredentialsAddress,
        bytes32 _mevRelay,

        FeeRecipient calldata _clientConfig,
        FeeRecipient calldata _referrerConfig
    ) external payable returns (address p2pSsvProxy) {
        checkOperators(_ssvOperators);
        _makeBeaconDeposits(_ssvValidators, _withdrawalCredentialsAddress);

        address feeDistributorInstance = _createFeeDistributor(_clientConfig, _referrerConfig);
        p2pSsvProxy = _createP2pSsvProxy(feeDistributorInstance);

        P2pSsvProxy(p2pSsvProxy).registerValidators(
            _ssvOperators,
            _ssvValidators,
            _cluster,
            feeDistributorInstance,
            _tokenAmount
        );

        emit P2pSsvProxyFactory__RegistrationCompleted(p2pSsvProxy, _mevRelay);
    }

    function allClientP2pSsvProxies(
        address _client
    ) external view returns (address[] memory) {
        return s_allClientP2pSsvProxies[_client];
    }

    function allP2pSsvProxies() external view returns (address[] memory) {
        return s_allP2pSsvProxies;
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
                bytes32(bytes20(_feeDistributorInstance))
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

    function owner() public view override(Ownable, OwnableBase, IOwnable) returns (address) {
        return super.owner();
    }
}
