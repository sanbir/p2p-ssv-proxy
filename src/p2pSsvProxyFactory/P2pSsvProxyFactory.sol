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


error P2pSsvProxyFactory__NotFeeDistributorFactory(address _passedAddress);

error P2pSsvProxyFactory__NotFeeDistributor(address _passedAddress);

error P2pSsvProxyFactory__NotP2pSsvProxy(address _passedAddress);

error P2pSsvProxyFactory__NotAllowedSsvOperatorOwner(address _caller);

error P2pSsvProxyFactory__MaxAllowedSsvOperatorIdsExceeded();

error P2pSsvProxyFactory__OldAndNewCountsShouldMatch(uint256 oldCount, uint256 newCount);

error P2pSsvProxyFactory__TryingToReplaceMoreThanExist(uint256 countToReplace, uint256 existingCount);

error P2pSsvProxyFactory__SsvOperatorOwnerAlreadyExists(address _ssvOperatorOwner);

error P2pSsvProxyFactory__SsvOperatorOwnerDoesNotExist(address _ssvOperatorOwner);

error P2pSsvProxyFactory__SsvOperatorNotAllowed(address _ssvOperatorOwner, uint64 _ssvOperatorId);

error P2pSsvProxyFactory__DuplicateIdsNotAllowed();

error P2pSsvProxyFactory__NotEnoughEtherPaidToCoverSsvFees(uint256 _needed, uint256 _paid);

/// @dev We assume, SSV won't either drop 7539x or soar higher than 100 ETH.
/// If it does, this contract won't be operational and another contract will have to be deployed.
error P2pSsvProxyFactory__SsvPerEthExchangeRateDividedByWeiOutOfRange();

error P2pSsvProxyFactory__SsvPerEthExchangeRateDividedByWeiNotSet();

contract P2pSsvProxyFactory is OwnableAssetRecoverer, OwnableWithOperator, ERC165, IP2pSsvProxyFactory {
    using EnumerableSet for EnumerableSet.AddressSet;

    IDepositContract private immutable i_depositContract;
    IFeeDistributorFactory private immutable i_feeDistributorFactory;
    IERC20 private immutable i_ssvToken;

    address private s_referenceFeeDistributor;
    P2pSsvProxy private s_referenceP2pSsvProxy;

    EnumerableSet.AddressSet private s_allowedSsvOperatorOwners;
    mapping(address => uint64[MAX_ALLOWED_SSV_OPERATOR_IDS]) private s_allowedSsvOperatorIds;

    mapping(address => address[]) private s_allClientP2pSsvProxies;
    address[] private s_allP2pSsvProxies;

    mapping(bytes4 => bool) private s_clientSelectors;
    mapping(bytes4 => bool) private s_operatorSelectors;

    /// @notice If 1 SSV = 0.007539 ETH, it should be 0.007539 * 10^18 = 7539000000000000
    uint256 private s_ssvPerEthExchangeRateDividedByWei;

    modifier onlySsvOperatorOwner() {
        bool isAllowed = s_allowedSsvOperatorOwners.contains(msg.sender);
        if (!isAllowed) {
            revert P2pSsvProxyFactory__NotAllowedSsvOperatorOwner(msg.sender);
        }
        _;
    }

    modifier onlyAllowedOperators(SsvOperator[] calldata _operators) {
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

        _;
    }

    constructor(
        address _feeDistributorFactory,
        address _referenceFeeDistributor
    ) {
        if (!ERC165Checker.supportsInterface(_feeDistributorFactory, type(IFeeDistributorFactory).interfaceId)) {
            revert P2pSsvProxyFactory__NotFeeDistributorFactory(_feeDistributorFactory);
        }
        i_feeDistributorFactory = IFeeDistributorFactory(_feeDistributorFactory);

        if (!ERC165Checker.supportsInterface(_referenceFeeDistributor, type(IFeeDistributor).interfaceId)) {
            revert P2pSsvProxyFactory__NotFeeDistributor(_referenceFeeDistributor);
        }

        s_referenceFeeDistributor = _referenceFeeDistributor;

        i_depositContract = (block.chainid == 1)
            ? IDepositContract(0x00000000219ab540356cBB839Cbe05303d7705Fa)
            : IDepositContract(0xff50ed3d0ec03aC01D4C79aAd74928BFF48a7b2b);

        i_ssvToken = (block.chainid == 1)
            ? IERC20(0x9D65fF81a3c488d585bBfb0Bfe3c7707c7917f54)
            : IERC20(0x3a9f01091C446bdE031E39ea8354647AFef091E7);
    }

    function setSsvPerEthExchangeRateDividedByWei(uint256 _ssvPerEthExchangeRateDividedByWei) external onlyOwner {
        if (_ssvPerEthExchangeRateDividedByWei < 10 ** 12 || _ssvPerEthExchangeRateDividedByWei > 10 ** 20) {
            revert P2pSsvProxyFactory__SsvPerEthExchangeRateDividedByWeiOutOfRange();
        }

        s_ssvPerEthExchangeRateDividedByWei = _ssvPerEthExchangeRateDividedByWei;
    }

    function setReferenceP2pSsvProxy(address _referenceP2pSsvProxy) external onlyOwner {
        if (!ERC165Checker.supportsInterface(_referenceP2pSsvProxy, type(IP2pSsvProxy).interfaceId)) {
            revert P2pSsvProxyFactory__NotP2pSsvProxy(_referenceP2pSsvProxy);
        }

        s_referenceP2pSsvProxy = P2pSsvProxy(_referenceP2pSsvProxy);
    }

    function setAllowedSelectorsForClient(bytes4[] calldata _selectors) external onlyOwner {
        uint256 count = _selectors.length;
        for (uint256 i = 0; i < count;) {
            s_clientSelectors[_selectors[i]] = true;

            unchecked {
                ++i;
            }
        }
    }

    function setAllowedSelectorsForOperator(bytes4[] calldata _selectors) external onlyOwner {
        uint256 count = _selectors.length;
        for (uint256 i = 0; i < count;) {
            s_operatorSelectors[_selectors[i]] = true;

            unchecked {
                ++i;
            }
        }
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

    function _setSsvOperatorIds(
        uint64[MAX_ALLOWED_SSV_OPERATOR_IDS] calldata _operatorIds,
        address _ssvOperatorOwner
    ) private {
        for (uint i = 0; i < _operatorIds.length;) {
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

        s_allowedSsvOperatorIds[_ssvOperatorOwner] = _operatorIds;
    }

    function setSsvOperatorIds(
        uint64[MAX_ALLOWED_SSV_OPERATOR_IDS] calldata _operatorIds
    ) external onlySsvOperatorOwner {
        _setSsvOperatorIds(_operatorIds, msg.sender);
    }

    function setSsvOperatorIds(
        uint64[MAX_ALLOWED_SSV_OPERATOR_IDS] calldata _operatorIds,
        address _ssvOperatorOwner
    ) external onlyOperatorOrOwner {
        _setSsvOperatorIds(_operatorIds, _ssvOperatorOwner);
    }

    function _clearSsvOperatorIds(address _ssvOperatorOwner) private {
        delete s_allowedSsvOperatorIds[_ssvOperatorOwner];
    }

    function clearSsvOperatorIds() external onlySsvOperatorOwner {
        _clearSsvOperatorIds(msg.sender);
    }

    function clearSsvOperatorIds(address _ssvOperatorOwner) external onlyOperatorOrOwner {
        _clearSsvOperatorIds(_ssvOperatorOwner);
    }

    function _makeBeaconDeposits(
        DepositData calldata _depositData,
        SsvValidator[] calldata _ssvValidators
    ) private {
        uint256 validatorCount = _ssvValidators.length;

        for (uint256 i = 0; i < validatorCount;) {
            // ETH deposit
            bytes memory withdrawalCredentials = abi.encodePacked(
                hex'010000000000000000000000',
                _depositData.withdrawalCredentialsAddress
            );
            i_depositContract.deposit{value: 32 ether}(
                _ssvValidators[i].pubkey,
                withdrawalCredentials,
                _depositData.signatures[i],
                _depositData.depositDataRoots[i]
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
            address(s_referenceP2pSsvProxy),
            bytes32(bytes20(_feeDistributorInstance))
        );
    }

    function createP2pSsvProxy(
        address _feeDistributorInstance
    ) external onlyOperatorOrOwner returns(address p2pSsvProxyInstance) {
        p2pSsvProxyInstance = _createP2pSsvProxy(_feeDistributorInstance);
    }

    function depositEthAndRegisterValidators(
        DepositData calldata _depositData,

        SsvOperator[] calldata _ssvOperators,
        SsvValidator[] calldata _ssvValidators,
        ISSVNetwork.Cluster calldata _cluster,
        uint256 _tokenAmount,

        bytes32 _mevRelay,

        FeeRecipient calldata _clientConfig,
        FeeRecipient calldata _referrerConfig
    ) external payable returns (address p2pSsvProxy) {
        _makeBeaconDeposits(_depositData, _ssvValidators);

        p2pSsvProxy = _registerValidators(_ssvOperators, _ssvValidators, _cluster, _tokenAmount, _mevRelay, _clientConfig, _referrerConfig);
    }

    function registerValidators(
        SsvOperator[] calldata _ssvOperators,
        SsvValidator[] calldata _ssvValidators,
        ISSVNetwork.Cluster calldata _cluster,
        uint256 _tokenAmount,

        bytes32 _mevRelay,

        FeeRecipient calldata _clientConfig,
        FeeRecipient calldata _referrerConfig
    ) external payable returns (address p2pSsvProxy) {
        uint256 exchangeRate = s_ssvPerEthExchangeRateDividedByWei;
        if (exchangeRate == 0) {
            revert P2pSsvProxyFactory__SsvPerEthExchangeRateDividedByWeiNotSet();
        }

        uint256 ssvTokensValueInWei = (_tokenAmount * exchangeRate) / 10**18;
        if (msg.value != ssvTokensValueInWei) {
            revert P2pSsvProxyFactory__NotEnoughEtherPaidToCoverSsvFees(ssvTokensValueInWei, msg.value);
        }

        p2pSsvProxy = _registerValidators(_ssvOperators, _ssvValidators, _cluster, _tokenAmount, _mevRelay, _clientConfig, _referrerConfig);
    }

    function _registerValidators(
        SsvOperator[] calldata _ssvOperators,
        SsvValidator[] calldata _ssvValidators,
        ISSVNetwork.Cluster calldata _cluster,
        uint256 _tokenAmount,

        bytes32 _mevRelay,

        FeeRecipient calldata _clientConfig,
        FeeRecipient calldata _referrerConfig
    ) private onlyAllowedOperators(_ssvOperators) returns (address p2pSsvProxy) {
        address feeDistributorInstance = _createFeeDistributor(_clientConfig, _referrerConfig);
        p2pSsvProxy = _createP2pSsvProxy(feeDistributorInstance);

        i_ssvToken.transfer(address(p2pSsvProxy), _tokenAmount);

        P2pSsvProxy(p2pSsvProxy).registerValidators(
            _ssvOperators,
            _ssvValidators,
            _cluster,
            feeDistributorInstance,
            _tokenAmount
        );

        emit P2pSsvProxyFactory__RegistrationCompleted(p2pSsvProxy, _mevRelay);
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
                address(s_referenceP2pSsvProxy),
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
        address referenceFeeDistributor_ = s_referenceFeeDistributor;

        feeDistributorInstance = i_feeDistributorFactory.predictFeeDistributorAddress(
            referenceFeeDistributor_,
            _clientConfig,
            _referrerConfig
        );
        if (feeDistributorInstance.code.length == 0) {
            // if feeDistributorInstance doesn't exist, deploy it
            i_feeDistributorFactory.createFeeDistributor(
                referenceFeeDistributor_,
                _clientConfig,
                _referrerConfig
            );
        }
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IP2pSsvProxyFactory).interfaceId || super.supportsInterface(interfaceId);
    }

    function owner() public view override(Ownable, OwnableBase, IOwnable) returns (address) {
        return super.owner();
    }

    function feeDistributorFactory() external view returns (address) {
        return address(i_feeDistributorFactory);
    }

    function allClientP2pSsvProxies(
        address _client
    ) external view returns (address[] memory) {
        return s_allClientP2pSsvProxies[_client];
    }

    function allP2pSsvProxies() external view returns (address[] memory) {
        return s_allP2pSsvProxies;
    }

    function isClientSelectorAllowed(bytes4 _selector) external view returns (bool) {
        return s_clientSelectors[_selector];
    }

    function isOperatorSelectorAllowed(bytes4 _selector) external view returns (bool) {
        return s_operatorSelectors[_selector];
    }

    function allowedSsvOperatorIds(address _ssvOperatorOwner) external view returns (uint64[MAX_ALLOWED_SSV_OPERATOR_IDS] memory) {
        return s_allowedSsvOperatorIds[_ssvOperatorOwner];
    }

    function allowedSsvOperatorOwners() external view returns (address[] memory) {
        return s_allowedSsvOperatorOwners.values();
    }

    function referenceFeeDistributor() external view returns (address) {
        return s_referenceFeeDistributor;
    }

    function referenceP2pSsvProxy() external view returns (address) {
        return address(s_referenceP2pSsvProxy);
    }

    function ssvPerEthExchangeRateDividedByWei() external view returns (uint256) {
        return s_ssvPerEthExchangeRateDividedByWei;
    }

    function neededAmountOfEtherToCoverSsvFees(uint256 _tokenAmount) external view returns (uint256) {
        return (_tokenAmount * s_ssvPerEthExchangeRateDividedByWei) / 10**18;
    }
}
