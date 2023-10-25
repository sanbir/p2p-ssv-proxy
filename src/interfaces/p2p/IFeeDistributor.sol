// SPDX-FileCopyrightText: 2023 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.10;

import "../@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "../structs/P2pStructs.sol";

/// @dev External interface of FeeDistributor declared to support ERC165 detection.
interface IFeeDistributor is IERC165 {

    /// @notice Returns the factory address
    /// @return address factory address
    function factory() external view returns (address);

    /// @notice Returns the service address
    /// @return address service address
    function service() external view returns (address);

    /// @notice Returns the client address
    /// @return address client address
    function client() external view returns (address);

    /// @notice Returns the client basis points
    /// @return uint256 client basis points
    function clientBasisPoints() external view returns (uint256);

    /// @notice Returns the referrer address
    /// @return address referrer address
    function referrer() external view returns (address);

    /// @notice Returns the referrer basis points
    /// @return uint256 referrer basis points
    function referrerBasisPoints() external view returns (uint256);

    /// @notice Returns the address for ETH2 0x01 withdrawal credentials associated with this FeeDistributor
    /// @dev Return FeeDistributor's own address if FeeDistributor should be CL rewards recipient
    /// Otherwise, return the client address
    /// @return address address for ETH2 0x01 withdrawal credentials
    function eth2WithdrawalCredentialsAddress() external view returns (address);
}
