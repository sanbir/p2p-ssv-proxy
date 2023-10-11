// SPDX-FileCopyrightText: 2023 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console.sol";
import "forge-std/console2.sol";

contract Integration is Test {
    function setUp() public {
        vm.createSelectFork("mainnet", 18275789);
    }

    function test_Main_Use_Case() public {
        console.log("MainUseCase started");
    }
}
