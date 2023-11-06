// SPDX-FileCopyrightText: 2023 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;

import "../@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "../structs/P2pStructs.sol";
import "../constants/P2pConstants.sol";
import "../interfaces/ssv/ISSVNetwork.sol";
import "../access/IOwnableWithOperator.sol";

/// @dev External interface of P2pSsvProxyFactory
interface IP2pSsvProxyFactory is IOwnableWithOperator, IERC165 {

    function depositEthAndRegisterValidators(
        DepositData calldata _depositData,
        address _withdrawalCredentialsAddress,

        SsvPayload calldata _ssvPayload,

        FeeRecipient calldata _clientConfig,
        FeeRecipient calldata _referrerConfig
    ) external payable returns (address p2pSsvProxy);

    function registerValidators(
        SsvPayload calldata _ssvPayload,
        FeeRecipient calldata _clientConfig,
        FeeRecipient calldata _referrerConfig
    ) external payable returns (address);

    function predictP2pSsvProxyAddress(
        address _feeDistributorInstance
    ) external view returns (address);

    function getAllClientP2pSsvProxies(
        address _client
    ) external view returns (address[] memory);

    function getAllP2pSsvProxies() external view returns (address[] memory);

    function isClientSelectorAllowed(bytes4 _selector) external view returns (bool);

    function isOperatorSelectorAllowed(bytes4 _selector) external view returns (bool);

    event P2pSsvProxyFactory__RegistrationCompleted(
        address indexed _proxy
    );

    event P2pSsvProxyFactory__P2pSsvProxyCreated(
        address indexed _p2pSsvProxy,
        address indexed _client,
        address indexed _feeDistributor
    );

    event P2pSsvProxyFactory__ReferenceFeeDistributorSet(
        address indexed _referenceFeeDistributor
    );

    event P2pSsvProxyFactory__SsvPerEthExchangeRateDividedByWeiSet(
        uint256 _ssvPerEthExchangeRateDividedByWei
    );

    event P2pSsvProxyFactory__ReferenceP2pSsvProxySet(
        address indexed _referenceP2pSsvProxy
    );

    event P2pSsvProxyFactory__AllowedSelectorsForClientSet(
        bytes4[] _selectors
    );

    event P2pSsvProxyFactory__AllowedSelectorsForOperatorSet(
        bytes4[] _selectors
    );

    event P2pSsvProxyFactory__AllowedSsvOperatorOwnersSet(
        address[] _allowedSsvOperatorOwners
    );

    event P2pSsvProxyFactory__AllowedSsvOperatorOwnersRemoved(
        address[] _allowedSsvOperatorOwners
    );

    event P2pSsvProxyFactory__SsvOperatorIdsSet(
        address indexed _ssvOperatorOwner,
        uint64[MAX_ALLOWED_SSV_OPERATOR_IDS] _operatorIds
    );

    event P2pSsvProxyFactory__SsvOperatorIdsCleared(
        address indexed _ssvOperatorOwner
    );
}
