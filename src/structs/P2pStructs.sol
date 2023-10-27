// SPDX-FileCopyrightText: 2023 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;

/// @dev 256 bit struct
/// @member basisPoints basis points (percent * 100) of EL rewards that should go to the recipient
/// @member recipient address of the recipient
struct FeeRecipient {
    uint96 basisPoints;
    address payable recipient;
}

struct SsvValidator {
    bytes pubkey;
    bytes sharesData;
}

struct SsvOperator {
    address owner;
    uint64 id;
    bytes32 snapshot;
    uint256 fee;
}
