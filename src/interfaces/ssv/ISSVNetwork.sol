// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.18;
import "./ISSVClusters.sol";

interface ISSVNetwork is ISSVClusters {
    function setFeeRecipientAddress(address feeRecipientAddress) external;
}
