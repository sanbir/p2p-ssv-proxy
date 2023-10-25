// SPDX-FileCopyrightText: 2023 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.10;

import "../@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "../access/IOwnable.sol";
import "../structs/P2pStructs.sol";

/// @dev External interface of P2pSsvProxyFactory
interface IP2pSsvProxyFactory is IOwnable, IERC165 {

    function depositEthAndRegisterValidators(
        SsvValidator[] calldata _ssvValidators,
        uint256 _tokenAmount,
        bytes32 _mevRelay,

        FeeRecipient calldata _clientConfig,
        FeeRecipient calldata _referrerConfig
    ) external returns (address p2pSsvProxy);

    function predictP2pSsvProxyAddress(
        FeeRecipient calldata _clientConfig,
        FeeRecipient calldata _referrerConfig
    ) external view returns (address p2pSsvProxy);

    function predictP2pSsvProxyAddress(
        address _referenceFeeDistributor,
        FeeRecipient calldata _clientConfig,
        FeeRecipient calldata _referrerConfig
    ) external view returns (address p2pSsvProxy);

    function allClientFeeDistributors(
        address _client
    ) external view returns (address[] memory);

    function allFeeDistributors() external view returns (address[] memory);

    event P2pSsvProxyFactory__RegistrationCompleted(
        address indexed _proxy,
        bytes32 indexed _mevRelay
    );

    event P2pSsvProxyFactory__P2pSsvProxyCreated(
        address indexed _p2pSsvProxy,
        address indexed _client,
        address indexed _feeDistributor
    );
}
