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

    /// @notice Emits when batch registration of validator with SSV is completed
    /// @param _proxy address of P2pSsvProxy that was used for registration and became the cluster owner
    event P2pSsvProxyFactory__RegistrationCompleted(
        address indexed _proxy
    );

    /// @notice Emits when a new P2pSsvProxy instance was deployed and initialized
    /// @param _p2pSsvProxy newly deployed P2pSsvProxy instance address
    /// @param _client client address
    /// @param _feeDistributor FeeDistributor instance address
    event P2pSsvProxyFactory__P2pSsvProxyCreated(
        address indexed _p2pSsvProxy,
        address indexed _client,
        address indexed _feeDistributor
    );

    /// @notice Emits when a new reference FeeDistributor has been set
    /// @param _referenceFeeDistributor new reference FeeDistributor address
    event P2pSsvProxyFactory__ReferenceFeeDistributorSet(
        address indexed _referenceFeeDistributor
    );

    /// @notice Emits when a new value for ssvPerEthExchangeRateDividedByWei has been set
    /// @param _ssvPerEthExchangeRateDividedByWei new value for ssvPerEthExchangeRateDividedByWei
    event P2pSsvProxyFactory__SsvPerEthExchangeRateDividedByWeiSet(
        uint256 _ssvPerEthExchangeRateDividedByWei
    );

    /// @notice Emits when a new reference P2pSsvProxy has been set
    /// @param _referenceP2pSsvProxy new reference P2pSsvProxy address
    event P2pSsvProxyFactory__ReferenceP2pSsvProxySet(
        address indexed _referenceP2pSsvProxy
    );

    /// @notice Emits when new selectors were allowed for clients
    /// @param _selectors newly allowed selectors
    event P2pSsvProxyFactory__AllowedSelectorsForClientSet(
        bytes4[] _selectors
    );

    /// @notice Emits when new selectors were allowed for operator
    /// @param _selectors newly allowed selectors
    event P2pSsvProxyFactory__AllowedSelectorsForOperatorSet(
        bytes4[] _selectors
    );

    /// @notice Emits when new SSV operator owner addresses have been allowed
    /// @param _allowedSsvOperatorOwners newly allowed SSV operator owner addresses
    event P2pSsvProxyFactory__AllowedSsvOperatorOwnersSet(
        address[] _allowedSsvOperatorOwners
    );

    /// @notice Emits when some SSV operator owner addresses have been removed from the allowlist
    /// @param _allowedSsvOperatorOwners disallowed SSV operator owner addresses
    event P2pSsvProxyFactory__AllowedSsvOperatorOwnersRemoved(
        address[] _allowedSsvOperatorOwners
    );

    /// @notice Emits when new SSV operator IDs have been set to the given SSV operator owner
    /// @param _ssvOperatorOwner SSV operator owner
    event P2pSsvProxyFactory__SsvOperatorIdsSet(
        address indexed _ssvOperatorOwner,
        uint64[MAX_ALLOWED_SSV_OPERATOR_IDS] _operatorIds
    );

    /// @notice Emits when operator IDs list has been cleared for the given SSV operator owner
    /// @param _ssvOperatorOwner SSV operator owner
    event P2pSsvProxyFactory__SsvOperatorIdsCleared(
        address indexed _ssvOperatorOwner
    );
}
