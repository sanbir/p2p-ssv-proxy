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
import "../p2pSsvProxyFactory/IP2pSsvProxyFactory.sol";
import "../assetRecovering/OwnableTokenRecoverer.sol";
import "./IP2pSsvProxy.sol";
import "../interfaces/p2p/IFeeDistributorFactory.sol";

/// @notice _referenceFeeDistributor should implement IFeeDistributor interface
/// @param _passedAddress passed address for _referenceFeeDistributor
error P2pSsvProxy__NotFeeDistributor(address _passedAddress);

/// @notice Should be a P2pSsvProxyFactory contract
/// @param _passedAddress passed address that does not support IP2pSsvProxyFactory interface
error P2pSsvProxy__NotP2pSsvProxyFactory(address _passedAddress);

/// @notice Throws if called by any account other than the client.
/// @param _caller address of the caller
/// @param _client address of the client
error P2pSsvProxy__CallerNotClient(address _caller, address _client);

error P2pSsvProxy__CallerNeitherOperatorNorOwner(address _caller, address _operator, address _owner);

error P2pSsvProxy__CallerNeitherOperatorNorOwnerNorClient(address _caller);

/// @notice Only factory can call `initialize`.
/// @param _msgSender sender address.
/// @param _actualFactory the actual factory address that can call `initialize`.
error P2pSsvProxy__NotP2pSsvProxyFactoryCalled(address _msgSender, IP2pSsvProxyFactory _actualFactory);

error P2pSsvProxy__AmountOfParametersError();

error P2pSsvProxy__SelectorNotAllowed(address caller, bytes4 selector);

contract P2pSsvProxy is OwnableTokenRecoverer, ERC165, IP2pSsvProxy {
    IP2pSsvProxyFactory private immutable i_p2pSsvProxyFactory;
    ISSVNetwork private immutable i_ssvNetwork;
    IERC20 private immutable i_ssvToken;

    IFeeDistributor private s_feeDistributor;

    /// @notice If caller not client, revert
    modifier onlyClient() {
        address clientAddress = getClient();

        if (clientAddress != msg.sender) {
            revert P2pSsvProxy__CallerNotClient(msg.sender, clientAddress);
        }
        _;
    }

    modifier onlyOperatorOrOwner() {
        address currentOwner = owner();
        address currentOperator = operator();

        if (currentOperator != msg.sender && currentOwner != msg.sender) {
            revert P2pSsvProxy__CallerNeitherOperatorNorOwner(msg.sender, currentOperator, currentOwner);
        }

        _;
    }

    modifier onlyOperatorOrOwnerOrClient() {
        address operator_ = operator();
        address owner_ = owner();
        address client_ = getClient();

        if (operator_ != msg.sender && owner_ != msg.sender && client_ != msg.sender) {
            revert P2pSsvProxy__CallerNeitherOperatorNorOwnerNorClient(msg.sender);
        }
        _;
    }

    /// @notice If caller not factory, revert
    modifier onlyP2pSsvProxyFactory() {
        if (msg.sender != address(i_p2pSsvProxyFactory)) {
            revert P2pSsvProxy__NotP2pSsvProxyFactoryCalled(msg.sender, i_p2pSsvProxyFactory);
        }
        _;
    }

    constructor(
        address _p2pSsvProxyFactory
    ) {
        if (!ERC165Checker.supportsInterface(_p2pSsvProxyFactory, type(IP2pSsvProxyFactory).interfaceId)) {
            revert P2pSsvProxy__NotP2pSsvProxyFactory(_p2pSsvProxyFactory);
        }
        i_p2pSsvProxyFactory = IP2pSsvProxyFactory(_p2pSsvProxyFactory);

        i_ssvNetwork = (block.chainid == 1)
            ? ISSVNetwork(0xDD9BC35aE942eF0cFa76930954a156B3fF30a4E1)
            : ISSVNetwork(0xC3CD9A0aE89Fff83b71b58b6512D43F8a41f363D);

        i_ssvToken = (block.chainid == 1)
            ? IERC20(0x9D65fF81a3c488d585bBfb0Bfe3c7707c7917f54)
            : IERC20(0x3a9f01091C446bdE031E39ea8354647AFef091E7);
    }

    function initialize(
        address _feeDistributor
    ) external onlyP2pSsvProxyFactory {
        s_feeDistributor = IFeeDistributor(_feeDistributor);

        i_ssvToken.approve(address(i_ssvNetwork), type(uint256).max);

        emit P2pSsvProxy__Initialized(_feeDistributor);
    }

    fallback() external {
        address caller = msg.sender;
        bytes4 selector = msg.sig;

        bool isAllowed = msg.sender == owner() ||
            (msg.sender == operator() && i_p2pSsvProxyFactory.isOperatorSelectorAllowed(selector)) ||
            (msg.sender == getClient() && i_p2pSsvProxyFactory.isClientSelectorAllowed(selector));

        if (!isAllowed) {
            revert P2pSsvProxy__SelectorNotAllowed(caller, selector);
        }

        (bool success, bytes memory data) = address(i_ssvNetwork).call(msg.data);
        if (success) {
            emit P2pSsvProxy__SuccessfullyCalledViaFallback(caller, selector);

            assembly {
                return(add(data, 0x20), mload(data))
            }
        } else {
            emit P2pSsvProxy__CallingViaFallbackFailed(caller, selector);

            // Decode the reason from the error data returned from the call and revert with it.
            revert(string(data));
        }
    }

    function _getOperatorIdsAndClusterIndex(
        SsvOperator[] calldata _ssvOperators
    ) private view returns(
        uint64[] memory operatorIds,
        uint64 clusterIndex
    ) {
        clusterIndex = 0;
        uint256 operatorCount = _ssvOperators.length;
        operatorIds = new uint64[](operatorCount);
        for (uint256 i = 0; i < operatorCount;) {
            operatorIds[i] = _ssvOperators[i].id;

            uint256 snapshot = uint256(_ssvOperators[i].snapshot);
            clusterIndex += uint64(snapshot >> 32) + (uint32(block.number) - uint32(snapshot)) * uint64(_ssvOperators[i].fee / 10_000_000);

            unchecked {
                ++i;
            }
        }
    }

    function _getBalance(
        ISSVNetwork.Cluster memory _cluster,
        uint64 _newIndex,
        uint64 _currentNetworkFeeIndex,
        uint256 _tokenAmount
    ) private pure returns(uint256 balance) {
        uint256 balanceBefore = _cluster.balance + _tokenAmount;

        uint64 networkFee = uint64(_currentNetworkFeeIndex - _cluster.networkFeeIndex) * _cluster.validatorCount;
        uint64 usage = (_newIndex - _cluster.index) * _cluster.validatorCount + networkFee;
        uint256 expandedUsage = usage * 10_000_000;
        balance = expandedUsage > balanceBefore? 0 : balanceBefore - expandedUsage;
    }

    function _registerValidator(
        uint256 i,
        uint64[] memory _operatorIds,
        ISSVNetwork.Cluster calldata _cluster,
        uint64 _clusterIndex,
        bytes calldata _pubkey,
        bytes calldata _sharesData,
        uint64 _currentNetworkFeeIndex,
        uint256 _balance
    ) private {
        ISSVClusters.Cluster memory cluster = ISSVClusters.Cluster({
            validatorCount: uint32(_cluster.validatorCount + i),
            networkFeeIndex: _currentNetworkFeeIndex,
            index: _clusterIndex,
            active: true,
            balance: _balance
        });

        i_ssvNetwork.registerValidator(
            _pubkey,
            _operatorIds,
            _sharesData,
            0,
            cluster
        );
    }

    function registerValidators(
        SsvPayload calldata _ssvPayload,
        address _feeDistributorInstance
    ) external onlyP2pSsvProxyFactory {
        (
            uint64[] memory operatorIds,
            uint64 clusterIndex
        ) = _getOperatorIdsAndClusterIndex(_ssvPayload.ssvOperators);

        uint64 currentNetworkFeeIndex = uint64(uint256(_ssvPayload.ssvSlot0) >> 192) + uint64(block.number - uint32(uint256(_ssvPayload.ssvSlot0))) * uint64(uint256(_ssvPayload.ssvSlot0) >> 128);

        uint256 balance = _getBalance(_ssvPayload.cluster, clusterIndex, currentNetworkFeeIndex, _ssvPayload.tokenAmount);

        i_ssvNetwork.registerValidator(
            _ssvPayload.ssvValidators[0].pubkey,
            operatorIds,
            _ssvPayload.ssvValidators[0].sharesData,
            _ssvPayload.tokenAmount,
            _ssvPayload.cluster
        );

        for (uint256 i = 1; i < _ssvPayload.ssvValidators.length;) {
            _registerValidator(
                i,
                operatorIds,
                _ssvPayload.cluster,
                clusterIndex,
                _ssvPayload.ssvValidators[i].pubkey,
                _ssvPayload.ssvValidators[i].sharesData,
                currentNetworkFeeIndex,
                balance
            );

            unchecked {
                ++i;
            }
        }

        i_ssvNetwork.setFeeRecipientAddress(_feeDistributorInstance);
    }

    function removeValidators(
        bytes[] calldata _pubkeys,
        uint64[] calldata _operatorIds,
        ISSVNetwork.Cluster[] calldata _clusters
    ) external onlyOperatorOrOwnerOrClient {
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
    ) external {
        address clusterOwner = address(this);
        uint256 validatorCount = _clusters.length;
        uint256 tokenPerValidator = _tokenAmount / validatorCount;

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

    /// @notice Returns the client address
    /// @return address client address
    function getClient() public view returns (address) {
        return s_feeDistributor.client();
    }

    function getFactory() external view returns (address) {
        return address(i_p2pSsvProxyFactory);
    }

    function owner() public view override(OwnableBase, IOwnable) returns (address) {
        return i_p2pSsvProxyFactory.owner();
    }

    function operator() public view returns (address) {
        return i_p2pSsvProxyFactory.operator();
    }

    function getFeeDistributor() external view returns (address) {
        return address(s_feeDistributor);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IP2pSsvProxy).interfaceId || super.supportsInterface(interfaceId);
    }
}
