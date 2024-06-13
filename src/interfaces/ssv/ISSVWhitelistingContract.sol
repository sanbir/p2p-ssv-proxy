// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

/// @dev https://github.com/ssvlabs/ssv-network/blob/c140c3c0de0ee7a64f3016f25c7820af6b752fd6/contracts/interfaces/external/ISSVWhitelistingContract.sol
interface ISSVWhitelistingContract {
    /// @notice Checks if the caller is whitelisted
    /// @param account The account that is being checked for whitelisting
    /// @param operatorId The SSV Operator Id which is being checked
    function isWhitelisted(address account, uint256 operatorId) external view returns (bool);
}
