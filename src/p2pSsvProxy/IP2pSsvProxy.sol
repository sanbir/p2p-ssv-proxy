// SPDX-FileCopyrightText: 2023 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;

import "../@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "../structs/P2pStructs.sol";
import "../access/IOwnableWithOperator.sol";

/// @dev External interface of P2pSsvProxy declared to support ERC165 detection.
interface IP2pSsvProxy is IOwnableWithOperator, IERC165 {

    event P2pSsvProxy__Initialized(
        address indexed _feeDistributor
    );

    event P2pSsvProxy__SuccessfullyCalledViaFallback(
        address indexed _caller,
        bytes4 indexed _selector
    );

    event P2pSsvProxy__CallingViaFallbackFailed(
        address indexed _caller,
        bytes4 indexed _selector
    );

    function initialize(
        address _feeDistributor
    ) external;

    /// @notice Returns the factory address
    /// @return address factory address
    function factory() external view returns (address);

    /// @notice Returns the client address
    /// @return address client address
    function client() external view returns (address);
}
