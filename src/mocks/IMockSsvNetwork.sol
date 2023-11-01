// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

interface IMockSsvNetwork {
    function setRegisterAuth(address userAddress, bool authOperators, bool authValidators) external;
}
