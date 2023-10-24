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
    address public constant owner = 0x000000005504F0f5CF39b1eD609B892d23028E57; // 0x5124fcC2B3F99F571AD67D075643C743F38f1C34;
    // address public constant operator = 0x388C818CA8B9251b393131C08a736A67ccB19297;
    address public constant p2pSsvTokenHolder = 0x000000005504F0f5CF39b1eD609B892d23028E57; // 0xF977814e90dA44bFA03b6295A0616a897441aceC;
    IERC20 public constant ssvToken = IERC20(0x3a9f01091C446bdE031E39ea8354647AFef091E7); // IERC20(0x9D65fF81a3c488d585bBfb0Bfe3c7707c7917f54);

    function setUp() public {
        // vm.createSelectFork("mainnet", 18140648);
        vm.createSelectFork("goerli", 9882317);

         vm.startPrank(owner);
         p2pSsvProxy = new P2pSsvProxy();
         vm.stopPrank();
    }

    function test_Main_Use_Case() public {
        console.log("MainUseCase started");

         vm.startPrank(p2pSsvTokenHolder);
         ssvToken.transfer(address(p2pSsvProxy), 50 ether);
         vm.stopPrank();

        uint256 tokenAmount = 11 ether;

        uint256 balance = ssvToken.balanceOf(address(p2pSsvProxy));
        console.log(balance);

        bytes[] memory pubkeys = new bytes[](2);
        pubkeys[0] = bytes(hex'ac5d83e2082ca5cf4b5822c5282bd998be2c0781e7c1edfef503db514aabbf9e57281269116763b425221c276ae6c1b9');
        pubkeys[1] = bytes(hex'b94fbfd66bac5375b0d144b772e2efa4d1f5f3deed94edce1e970793ab8cc21ee0bd1c474428ab33cce5e9cbe2498c0c');

        uint64[] memory operatorIds = new uint64[](4);
        operatorIds[0] = 1;
        operatorIds[1] = 2;
        operatorIds[2] = 3;
        operatorIds[3] = 4;


        bytes[] memory sharesData = new bytes[](2);
        sharesData[0] = bytes(hex'9508c8ee252655f6bb0ec399973220be6a4c6bf212e3c549a9240071ef7913b2be735ada8f381c8e96cfdace96f488090658c56e9d4c2bfe7f438a47cc9ff6b072f53df891c1314590f176988709f36495c2a87322f1825432082a0f926623f98fd0e3b926da0a75ba0f17491484dd94fc7f1c6636fc93f46e7e3b3ead49bcb80a305521fb8672c8f1748f11ad4aa6e6b5576a428239349005af8d9c9f241b7c34cdf4d031e77a758a83fa1ea8172feb5dd3be87fe4d4925cc30545d8caf26c998d525738482c9fa907c74f46c4169659dd2b7efc56189954cdfb309645ac5f81b89c4e268ade37e0de5ca4a5f4015db95b5d4237cd31ecd413cd4e5ba4180bec0b51a0015ed52d545d91522a9ab9b3421c85de7c688e757bf7698932308dc2a5d15a73d87d7b585127dc0d8b0825c16cbdecd22112832fd8575807c10f0910ac6fef995a78121f0409da98b31e78549e7b0f982a856fea16bb3e8ec2e015889c7f0bf0e63a4a06eb451a8547afb35e1ba43f9dbec567f8878a06f6c17c3ae63c93377aeced75825879d822469d2eb46bf0bd073e4393f8e92a91b529507bc3029d849bdef91c1ff8dedb9f1ab714b17e5e30dcdb0deef4e6de9edce046a5d0e5c7e6275befd7bf389d41658dfc272853fe1134b8636e0a5e87b30b930849012d4fbcfbf816b48575c5de6891093ffbeef87d92d9642ca19878863d32d05a3b8cabc0bf1a8de949bfebf7a1db6627d1cdb5acd8d90efd1245a8e2c0d110ae00d0cf66fd23ecde101a3a5f4305b9afb1603c4c9bb1569f26102c92c6c91f4b3405ba5c14aa59c2a04866c2391d81f1b1e3fc8f2f32e5f12c3408f9b25d0593621b56243d1f8a2f6fde4819bf6b8c80515c4011759d33eb0750f8d98b63c86dd578cee20d6917166ee24680df71ce09d50772834ecc287cee515cecf7fbdb89cb68cb7acfc19beefaca3a0b25ae0b12d116e8ccbb33837ad752790bea21e387b38bcd5dbfe05d54ab111ad561f38e86aa7bc3023f7dda7bfeff2ca8283ac658869d08669d75c0c3ce5be2dda05c747d9fb6ee7be3e4cc1dd5d5838e817fc281f30397ae21bfc61a2304e9e0fcd106ea9d835cccd7cb60f3dd21e64a3b63acdd5ca9c59ae4f2f348eabf93dd0a039ad1a47a5cf83869cec24b0f230278509cec35387fff2bfbb905d6a96a918fd48aa8ea9ebfec7c7ad54c69cf4272544363ace218b2a7b8125845b197fba5ae5c51f2163c9900ae914796ecb58abe8ddbd670798d5e201aa7725d90394db7d89eac434341bf56e09de4b5ef80a02ca67bb05f506089e2f33fd30281a0eaba6a3718cc74c39dd6918bcfc69cf344912371044ab6bc5a367456bca34e889c7c10b5eaa4a7614b6298d0c274eda7aa645d3cbf1d6d49c04f3be0017ffa358b5af54dc375c514284ed4c2e68b29ac81878fdebaff5e9643e937162e713088c9ba5fd62fbe9ea906b49c28356d9f1de54ac597265c7a175ab71047985443895c02df42bf91d923136a861cf6597130af6b4660b5dc445393406a4145febc2272517400c0405e3b70c86f39603b71ef9fee133b1a288789d8018c64c6c03c6519bca56ce9f262e36f6efda4c801d55959bd55aa2b48b2d8817dd4884ff0faa57b24c6419647a4d95e87f623edc819c2f2cc0cf2fbef584a47007c554d706a8531db23fdfb34a129d32776046ba43debadda1318910b0a81693b4b8d76e9355a10111e9baf11d5ad7116d2e83fe82acb0f58e69c919be45bcf23f32c1f653e5bd2333320540ee25ef31d76a895de9078785b2ccc0e901932d9ca2ca03ee9a5fdba7c9b00c74702f9a4a1b0469e712bcb4967f610ead3fc0');
        sharesData[1] = bytes(hex'89d39f2753b553ca16397d36fca7cf5678bafe2c01f162ca06f7ce9fe16ee0995b94c0d1ee36b3079be6cbf4c731b9f416db749eee7d5d999bd56c4f11f8bb07d1d819a6d4c7d0b6709101216123312a16be1fb648dde921811e3ce935fd8a3eb608e30830d3e7b2a53c06ff8923b732fb94a4955c8d267a0161deecec34b3a56cd63fd06d92f8c2b58237f531264b93918620ce46f01edde253c58866eba81b5f19a29fc62f9324f4008e62863cadcde02343621a3965bd7dd697a2404d585a835b0cbefe41f0e221b210bdb6bfb0d7dbc8cd8cf7b419222eeb1d17bc0610d7c0fa2045e8df1f2f35b663757a1522c194a333dee6392d50353ab0f685a7ed8608975f46c74c778a58a63ef916ff260625cf3aed05fa082b17683da4e3771b46b80034cebf1f71453d32cf25a147477945adbc001051bb4c96ad4ec2a9ef68e85040bfae0fe0b72e8b1289580825a7a096fcb40034957d2ca1c98ab9f87624b76800b095875219b2c571c375bf348ec51c059624926c747d04eef6efc1b1a0b0527f8d9f62d2ceba99cf89e161ff376244cfdbcd6886b5dd9bd0d1a28ba312fd9acd5064a7e1f9cc9cdc33b2d46b1d0dbfc451dd07b903d9c0e756776b980b1144f41549324a0735055eaa2fe7b1e6f68aee8b08aaeee6c50148f97cdd13c86fb7973eb590edcbcdbaccbb8a7fbed672c2ee9a76d7d24c475cc1f9c70751a417e3df3e0ac03583e6ced99b308fb4c67fa58e79be03f2ccdbf280caf667b12f92566f91b51d23388027819c8eaa027863fb61f8ecea4a47e9a223e008a3bf26ef536a7e27fb3b3ce998041c85cb93c7226aa96a75d0aee03202f480965cac6f57ab39174ed2290803f6f0ccd81df3439a12d5623676708c69b2f7333d32ff5bba7eda36362c0e26516a5d0389dee7afbff66b0ee39ea2202b42d54fa3f4a9731c65435a75d9852c2e52a29cf849f4d94ae88a6c3abfe90da0722fe2639421be8a6f753f32884418311ca2f668bb6e97e953557b84a706666a4c935fc4547af1ae6ca313ee9077c083e39208fbe0b0f97d761b6b59bcc22b29837f915adc3ccab2138fffdcf6fc37efd6e97c409faa96dee0a5a3ff68669121e99a13db559e77ce4224bfc346a081003bf10aad8bc6767f07e4099e67a5741b5c58335ea7790b75425d573ccdbd6fc5931494cd7bc9fb1ca202e41f358b57d5bf17a0dd3c0f3cd9f7f68f5ba6bd00d8a5e056ed247da2b5b189f35f0468351294598d827c8df43b5134c9622c5b53345efa01619b9aa86128159b18810607d7ad31b565c0b72251026d402d86e1b8605a0f6b6d4a80664ed7b17b5629a14c62caba45ee5d9021a1720699cbcafd3de77317e6a1ad5228e8b2f08de5c148b1a13f228b1778dc6348756b4f0596c481dff05c0cba56f551879c43f58bd34861f2a0726ee7fdc94e7b035a5af29e112c79bb10a5e0ed3afa46f48b3d905d0217cc244068375d2ac5bdad0ad9a979f56170d7e7d752fa7c9a4049940b31e3310c89b3f75fe53a3b0f1f357f48aaccb432bde0c066fd081a9bb0424d8cea7f79411cd918efaed88f39567539fed30e9798b91fdfedd20ba6e8cf08c13f369f02257b4918a5da227e6307386ca72f06d403df3e07f39a3813ae31134cff81791248f25e925db5f380eba56c801be2e8df7f35fc98a27215712e5080ca156d9fec2ffd77026b4b4d66b61b0d7ad21cdabc92a93f062ab587734d2f7ebeae74effbd1ce3cec41b1ed0de6a0c154dc3031dcd6e0e4eeb9812e681662de6be903c1842109af3ec8d49a284611599b6a0bb0f0a1e80b3da826d91a733fbffc9213c6f16e1205833bb433b8e4ff');

        ISSVClusters.Cluster[] memory clusters = new ISSVClusters.Cluster[](2);
        clusters[0] = ISSVClusters.Cluster({
            validatorCount: 0,
            networkFeeIndex: 0,
            index: 0,
            active: true,
            balance: 0
        });
        clusters[1] = ISSVClusters.Cluster({
            validatorCount: 1,
            networkFeeIndex: 0,
            index: 259695089520,
            active: true,
            balance: 5500000000000000000
        });

        vm.startPrank(owner);

        p2pSsvProxy.registerValidators(tokenAmount, pubkeys, operatorIds, sharesData, clusters);

//        ISSVNetwork(0xC3CD9A0aE89Fff83b71b58b6512D43F8a41f363D).registerValidator(
//            pubkeys[0],
//                operatorIds,
//                sharesData[0],
//                tokenAmount,
//                clusters[0]
//        );

        vm.stopPrank();

        console.log("MainUseCase finsihed");
    }
}
