// SPDX-FileCopyrightText: 2023 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;

import "../@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "../structs/P2pStructs.sol";
import "../interfaces/ssv/ISSVNetwork.sol";
import "../access/IOwnableWithOperator.sol";

/// @dev External interface of P2pSsvProxyFactory
interface IP2pSsvProxyFactory is IOwnableWithOperator, IERC165 {

    function depositEthAndRegisterValidators(
        DepositData calldata _depositData,
        address _withdrawalCredentialsAddress,

        SsvPayload calldata _ssvPayload,

        bytes32 _mevRelay,

        FeeRecipient calldata _clientConfig,
        FeeRecipient calldata _referrerConfig
    ) external payable returns (address p2pSsvProxy);

    function registerValidators(
        SsvPayload calldata _ssvPayload,
        bytes32 _mevRelay,
        FeeRecipient calldata _clientConfig,
        FeeRecipient calldata _referrerConfig
    ) external payable returns (address);

    function predictP2pSsvProxyAddress(
        address _feeDistributorInstance
    ) external view returns (address);

    function getAllClientP2pSsvProxies(
        address _client
    ) external view returns (address[] memory);

    function getAllP2pSsvProxies() external view returns (address[] memory);

    function isClientSelectorAllowed(bytes4 _selector) external view returns (bool);

    function isOperatorSelectorAllowed(bytes4 _selector) external view returns (bool);

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
