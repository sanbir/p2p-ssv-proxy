// SPDX-FileCopyrightText: 2023 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;

import "../@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "../structs/P2pStructs.sol";
import "../access/IOwnableWithOperator.sol";

/// @dev External interface of P2pSsvProxy declared to support ERC165 detection.
interface IP2pSsvProxy is IOwnableWithOperator, IERC165 {

    /// @notice Emits when P2pSsvProxy instance is initialized
    /// @param _feeDistributor FeeDistributor instance that determines the identity of this P2pSsvProxy instance
    event P2pSsvProxy__Initialized(
        address indexed _feeDistributor
    );

    /// @notice Emits when the function was called successfully on SSVNetwork via fallback
    /// @param _caller caller of P2pSsvProxy
    /// @param _selector selector of the function from SSVNetwork
    event P2pSsvProxy__SuccessfullyCalledViaFallback(
        address indexed _caller,
        bytes4 indexed _selector
    );

    /// @notice Emits when an error occurred during the call of SSVNetwork via fallback
    /// @param _caller caller of P2pSsvProxy
    /// @param _selector selector of the function from SSVNetwork
    event P2pSsvProxy__CallingViaFallbackFailed(
        address indexed _caller,
        bytes4 indexed _selector
    );

    /// @notice Initialize the P2pSsvProxy instance
    /// @dev Should only be called by P2pSsvProxyFactory
    /// @param _feeDistributor FeeDistributor instance that determines the identity of this P2pSsvProxy instance
    function initialize(
        address _feeDistributor
    ) external;

    /// @notice Returns the factory address
    /// @return address factory address
    function getFactory() external view returns (address);

    /// @notice Returns the client address
    /// @return address client address
    function getClient() external view returns (address);
}
