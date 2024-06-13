// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

/// @dev Mock for testing. NOT to be deployed on mainnet!!!
interface IChangeOperator {
    function changeOperator(address _newOperator) external;
}
