// SPDX-FileCopyrightText: 2023 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.10;

import "../@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "../structs/P2pStructs.sol";

/// @dev External interface of FeeDistributor declared to support ERC165 detection.
interface IFeeDistributor is IERC165 {

    /// @notice Set client address.
    /// @dev Could not be in the constructor since it is different for different clients.
    /// _referrerConfig can be zero if there is no referrer.
    /// @param _clientConfig address and basis points (percent * 100) of the client
    /// @param _referrerConfig address and basis points (percent * 100) of the referrer.
    function initialize(
        FeeRecipient calldata _clientConfig,
        FeeRecipient calldata _referrerConfig
    ) external;

    /// @notice Increase the number of deposited validators.
    /// @dev Should be called when a new ETH2 deposit has been made
    /// @param _validatorCountToAdd number of newly deposited validators
    function increaseDepositedCount(
        uint32 _validatorCountToAdd
    ) external;

    /// @notice Request a voluntary exit of validators
    /// @dev Should be called by the client when they want to signal P2P that certain validators need to be exited
    /// @param _pubkeys pubkeys of validators
    function voluntaryExit(
        bytes[] calldata _pubkeys
    ) external;

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
