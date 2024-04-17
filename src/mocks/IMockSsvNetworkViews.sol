// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

/// @dev Mock for testing. NOT to be deployed on mainnet!!!
interface IMockSsvNetworkViews {
    /// @notice Gets the operator fee
    /// @param operatorId The ID of the operator
    /// @return fee The fee associated with the operator (SSV). If the operator does not exist, the returned value is 0.
    function getOperatorFee(uint64 operatorId) external view returns (uint256 fee);
}
