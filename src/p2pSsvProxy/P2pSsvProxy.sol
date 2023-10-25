// SPDX-FileCopyrightText: 2023 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;

import "../@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

import "../constants/P2pConstants.sol";
import "../interfaces/ssv/ISSVNetwork.sol";
import "../access/OwnableWithOperator.sol";
import "../structs/P2pStructs.sol";
import "../interfaces/IDepositContract.sol";
import "../p2pSsvProxyFactory/IP2pSsvProxyFactory.sol";
import "../assetRecovering/OwnableTokenRecoverer.sol";
import "./IP2pSsvProxy.sol";
import "../interfaces/p2p/IFeeDistributorFactory.sol";

/// @notice _referenceFeeDistributor should implement IFeeDistributor interface
/// @param _passedAddress passed address for _referenceFeeDistributor
error P2pSsvProxy__NotFeeDistributor(address _passedAddress);

/// @notice Should be a FeeDistributorFactory contract
/// @param _passedAddress passed address that does not support IFeeDistributorFactory interface
error P2pSsvProxy__NotFeeDistributorFactory(address _passedAddress);

/// @notice Should be a P2pSsvProxyFactory contract
/// @param _passedAddress passed address that does not support IP2pSsvProxyFactory interface
error P2pSsvProxy__NotP2pSsvProxyFactory(address _passedAddress);

/// @notice Throws if called by any account other than the client.
/// @param _caller address of the caller
/// @param _client address of the client
error P2pSsvProxy__CallerNotClient(address _caller, address _client);

/// @notice Only factory can call `initialize`.
/// @param _msgSender sender address.
/// @param _actualFactory the actual factory address that can call `initialize`.
error P2pSsvProxy__NotP2pSsvProxyFactoryCalled(address _msgSender, IP2pSsvProxyFactory _actualFactory);


contract P2pSsvProxy is OwnableTokenRecoverer, OwnableWithOperator, ERC165, IP2pSsvProxy {
    IP2pSsvProxyFactory internal immutable i_p2pSsvProxyFactory;
    ISSVNetwork public immutable i_ssvNetwork;
    IERC20 public immutable i_ssvToken;

    IFeeDistributor public s_feeDistributor;

    /// @notice If caller not client, revert
    modifier onlyClient() {
        address clientAddress = client();

        if (clientAddress != msg.sender) {
            revert P2pSsvProxy__CallerNotClient(msg.sender, clientAddress);
        }
        _;
    }

    /// @notice If caller not factory, revert
    modifier onlyP2pSsvProxyFactory() {
        if (msg.sender != address(i_p2pSsvProxyFactory)) {
            revert P2pSsvProxy__NotP2pSsvProxyFactoryCalled(msg.sender, i_p2pSsvProxyFactory);
        }
        _;
    }

    constructor(
        address _p2pSsvProxyFactory
    ) {
        if (!ERC165Checker.supportsInterface(_p2pSsvProxyFactory, type(IP2pSsvProxyFactory).interfaceId)) {
            revert P2pSsvProxy__NotP2pSsvProxyFactory(_p2pSsvProxyFactory);
        }
        i_p2pSsvProxyFactory = IP2pSsvProxyFactory(_p2pSsvProxyFactory);

        i_ssvNetwork = (block.chainid == 1)
            ? ISSVNetwork(0xDD9BC35aE942eF0cFa76930954a156B3fF30a4E1)
            : ISSVNetwork(0xC3CD9A0aE89Fff83b71b58b6512D43F8a41f363D);

        i_ssvToken = (block.chainid == 1)
            ? IERC20(0x9D65fF81a3c488d585bBfb0Bfe3c7707c7917f54)
            : IERC20(0x3a9f01091C446bdE031E39ea8354647AFef091E7);

        i_ssvToken.approve(address(i_ssvNetwork), type(uint256).max);
    }

    function initialize(
        address _feeDistributor
    ) external onlyP2pSsvProxyFactory {
        s_feeDistributor = _feeDistributor;
    }

    function registerValidators(
        SsvValidator[] calldata _ssvValidators,
        address feeDistributorInstance,
        uint256 _tokenAmount
    ) external {
        uint256 validatorCount = _ssvValidators.length;
        uint256 tokenPerValidator = _tokenAmount / validatorCount;

        for (uint256 i = 0; i < validatorCount;) {
            i_ssvNetwork.registerValidator(
                _ssvValidators[i].pubkey,
                _operatorIds,
                _sharesData[i],
                tokenPerValidator,
                _clusters[i]
            );

            unchecked {
                ++i;
            }
        }

        i_ssvNetwork.setFeeRecipientAddress(feeDistributorInstance);
    }

    function removeValidators(
        bytes[] calldata _pubkeys,
        uint64[] calldata _operatorIds,
        ISSVNetwork.Cluster[] calldata _clusters
    ) external onlyOperatorOrOwner {
        uint256 validatorCount = _pubkeys.length;

        if (!(
            _clusters.length == validatorCount
        )) {
            revert P2pSsvProxy__AmountOfParametersError();
        }

        for (uint256 i = 0; i < validatorCount;) {
            i_ssvNetwork.removeValidator(_pubkeys[i], _operatorIds, _clusters[i]);

            unchecked {
                ++i;
            }
        }
    }

    function liquidate(
        uint64[] calldata _operatorIds,
        ISSVNetwork.Cluster[] calldata _clusters
    ) external onlyOperatorOrOwner {
        address clusterOwner = address(this);
        uint256 validatorCount = _clusters.length;

        for (uint256 i = 0; i < validatorCount;) {
            i_ssvNetwork.liquidate(clusterOwner, _operatorIds, _clusters[i]);

            unchecked {
                ++i;
            }
        }
    }

    function reactivate(
        uint256 _tokenAmount,
        uint64[] calldata _operatorIds,
        ISSVNetwork.Cluster[] calldata _clusters
    ) external onlyOperatorOrOwner {
        uint256 tokenPerValidator = _tokenAmount / _clusters.length;
        uint256 validatorCount = _clusters.length;

        for (uint256 i = 0; i < validatorCount;) {
            i_ssvNetwork.reactivate(_operatorIds, tokenPerValidator, _clusters[i]);

            unchecked {
                ++i;
            }
        }
    }

    function depositToSSV(
        uint256 _tokenAmount,
        uint64[] calldata _operatorIds,
        ISSVNetwork.Cluster[] calldata _clusters
    ) external onlyOperatorOrOwner {
        address clusterOwner = address(this);
        uint256 tokenPerValidator = _tokenAmount / _clusters.length;
        uint256 validatorCount = _clusters.length;

        for (uint256 i = 0; i < validatorCount;) {
            i_ssvNetwork.deposit(clusterOwner, _operatorIds, tokenPerValidator, _clusters[i]);

            unchecked {
                ++i;
            }
        }
    }

    function withdrawFromSSV(
        uint256 _tokenAmount,
        uint64[] calldata _operatorIds,
        ISSVNetwork.Cluster[] calldata _clusters
    ) external onlyOperatorOrOwner {
        uint256 tokenPerValidator = _tokenAmount / _clusters.length;
        uint256 validatorCount = _clusters.length;

        for (uint256 i = 0; i < validatorCount;) {
            i_ssvNetwork.withdraw(_operatorIds, tokenPerValidator, _clusters[i]);

            unchecked {
                ++i;
            }
        }
    }

    function withdrawSSVTokens(
        address _to,
        uint256 _amount
    ) external onlyOwner {
        i_ssvToken.transfer(_to, _amount);
    }

    function setFeeRecipientAddress(
        address feeRecipientAddress
    ) external onlyOperatorOrOwner {
        i_ssvNetwork.setFeeRecipientAddress(feeRecipientAddress);
    }

    /// @notice Returns the client address
    /// @return address client address
    function client() public view returns (address) {
        return s_feeDistributor.client();
    }
}
