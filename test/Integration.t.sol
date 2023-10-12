// SPDX-FileCopyrightText: 2023 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console.sol";
import "forge-std/console2.sol";

import "../src/P2pSsvProxy.sol";
import "../src/interfaces/ssv/ISSVClusters.sol";

contract Integration is Test {
    P2pSsvProxy public p2pSsvProxy;
    address public constant owner = 0x5124fcC2B3F99F571AD67D075643C743F38f1C34;
    address public constant operator = 0x388C818CA8B9251b393131C08a736A67ccB19297;
    address public constant p2pSsvTokenHolder = 0xF977814e90dA44bFA03b6295A0616a897441aceC;
    IERC20 public constant ssvToken = IERC20(0x9D65fF81a3c488d585bBfb0Bfe3c7707c7917f54);

    function setUp() public {
        vm.createSelectFork("mainnet", 18275789);

        vm.startPrank(owner);
        p2pSsvProxy = new P2pSsvProxy();
        vm.stopPrank();
    }

    function test_Main_Use_Case() public {
        console.log("MainUseCase started");

        vm.startPrank(p2pSsvTokenHolder);
        ssvToken.transfer(address(p2pSsvProxy), 100 ether);
        vm.stopPrank();

        uint256 tokenAmount = 1.7 ether;

        bytes[] memory pubkeys = new bytes[](1);
        pubkeys[0] = bytes(hex'8c4c5a9b36b47588a880cc01e9fc374437c7e09f25cc365230c3a9a39b9d3432a50a0a804c6f0b47d9095537c8a4d9b6');

        uint64[] memory operatorIds = new uint64[](4);
        operatorIds[0] = 1;
        operatorIds[1] = 3;
        operatorIds[2] = 4;
        operatorIds[3] = 5;


        bytes[] memory sharesData = new bytes[](1);
        sharesData[0] = bytes(hex'ad36f28f65164107dd74fec1e2b8f2c200ff5030cfba39cc299698b9c9d3165bd5e9d280c550b74ae6d46b04c115d5901351ed31679349133879450f84f147a56ef5b4ce3cca6ce3eec080e405d2b26a872e4bf8ba928fbba294a236d35eba50a2c33611465a1aeb9444af7eafb488427ebb4619f060836cad4f38929a98dd2738cb9ff3ea6db4e26c46483baf644593a06b9f6f8e4f77e629f09a3e117a7f3fc7ed277e6b24673117cfda07854a8ae191e2cd29171f42863d1fc16d6db466939082ef0d4e8b30d419bccb22a60c3b4f44adacb2b89dc2a6a20e7f66e71c7c46d4c16e7d0ef29316c733ffb223512ab2918d19ea4d75566671d66e0e36d3f7e2f9ed7aa73682face8c02c946c9b67279dbc35a3dc1ee782929d05f8569bbcfce9a6736ef396cf00e8a7112d1f19405f910e5c5fb4558cb7db8a62456722c89ec4c4097a35d8219a98f1c8d8cc4cdec8d219c2d37904ee46183962eac69218dfdd18cc390a1fe7561a17b88c6ec7a802ba37d277a3e49322b87cfd3fdb8f43b7b68af80ee203f8868c93d3f5be1ecc54429315f8a8e890a847bbca2c74df89095422451103a507576f160078f52fc7d54ce4197ac1eb79d84bd5f82a5ff28024246d95485ec0c3014e0bce89ef03bd5d1c2a9f698c7891fe13a09390e59081048c8f6cd7a26f3c227d923e0d04b3799e0731ee75b99258129f295000972f66d7a24c625c686c1d55e9ae68f61f95c0d30bda649b81842452f1dcd41a09fa3d1094674d2974f180094db01fd7fe258316ca4f81530acc22f78632caca75ee0e9326003a832a02a587c663b13ae849fb5f8cdf4a78895b35998d04732e23e3e522af8a89da49737613e564469920a64075517f370fc234b7b7937f3fd39161bee0e93b23148b6423391bec8ea11f9d82e8c4343d91617444bdc34fb8c81dda0fe7251d680dff2472094691e6131f806994ecbe14a3632854ad669f6a4f82014f818be3c57d3343d43cf7abaeea1db05aeed4fcfdd72628895f1cd358675712beff835fb8a96fd707121bc1948d14e0fe180194d6b210c28c132394916ef70775e230cac2eff7596335f6439c08a6f17308fa3d5709247f9d4f84ddd603f9cdd2ae1931d84da0e34a370d07bccb5c8ae8046e106b313e784f6ad010803a13e2e08e5a6cc64210b2ae63555970da11e29c84b29fa47a75e26547b57ab6471b3b556ff2c5b6a38489d3e1583722229d056e17e1cc0b5c0960d3895be4f8ea4010f951c19bc4dd833b3f3467172fc3c55452665a47dc4eeeae988923c71b7bb0983f1a12430b5fbeea03a00bee9c3402c839e61178f6e68f55b54fc7f577d5eeb31491dc9e3722638879df4689be5ffafe13af5d351f0f152e74cc0b1a5c832330ddec27527c7fdcaef4b787d3f6ced3f8beea91f8618aa4d2fe4f9fc0461bb8229b59ab57e5266387e5f233cd75a320fcc1852df85d354961f5d0709cbd6f844c5fd8525848a55b0e5d2798f8fbf1485a1a2c1f86194469925a054880939658a4a887fc65a3f28c65ca53ebd8b882b453791f9bd7f55c9cdcc89781af1d3f663cb33a5e8049701fed0b2f4b375551a57955d927f59c4b911dd26b5b8c25928b9edb293a1f3d27f46587b8c7d94eaacbfbcb13cd10ed91bd54c0bbdd86dda0b11b016b3900b973eb873601675ede8f876cfd009b29499496a3c3e39fd720f6e2c391f734c75a81500f6a23b72c3b144a2c66e7030e7c61178ecc703923c88e35537a4188bcb85c652980b25034e5849e500fba5b221fffb1ef77d782ce2cbe9da1f38e7936fc4fe8b3de884ccb8c4b673952e80012126c02c3413d05f363860e7d1ab8c');

        ISSVClusters.Cluster[] memory clusters = new ISSVClusters.Cluster[](1);
        clusters[0] = ISSVClusters.Cluster({
            validatorCount: 0,
            networkFeeIndex: 0,
            index: 0,
            active: true,
            balance: 0
        });

        vm.startPrank(owner);
        p2pSsvProxy.registerValidators(tokenAmount, pubkeys, operatorIds, sharesData, clusters);
        vm.stopPrank();

        console.log("MainUseCase finsihed");
    }
}
