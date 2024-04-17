// SPDX-FileCopyrightText: 2023 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console.sol";
import "forge-std/console2.sol";

import "../src/interfaces/ssv/ISSVClusters.sol";
import "../src/interfaces/ssv/ISSVViews.sol";
import "../src/p2pSsvProxyFactory/P2pSsvProxyFactory.sol";
import "../src/structs/P2pStructs.sol";
import "../src/mocks/IChangeOperator.sol";
import "../src/mocks/IMockSsvNetworkViews.sol";

contract HoleskyIntegration is Test {
    address public constant owner = 0x000000005504F0f5CF39b1eD609B892d23028E57;
    IERC20 public constant ssvToken = IERC20(0xad45A78180961079BFaeEe349704F411dfF947C6);
    address public constant ssvNetworkAddress = 0x38A4794cCEd47d3baf7370CcC43B560D3a1beEFA;
    IMockSsvNetworkViews public constant ssvNetworkViews = IMockSsvNetworkViews(0x352A18AEe90cdcd825d1E37d9939dCA86C00e281);
    P2pSsvProxyFactory public p2pSsvProxyFactory;
    address payable public constant client = payable(address(0x21d29512D080160F6E56406630c0779C67B5911f));
    uint64[4] public operatorIds = [uint64(236), 306, 315, 400];

    function setUp() public {
        vm.createSelectFork("holesky", 1328440);

        address feeDistributorFactory = address(0xB7C5d2e55c64D508C8927EFD37DF8a1db8431B44);
        address referenceFeeDistributor = address(0x3AB5252B37425842B9f253821e946Fc5d24A2cE4);

        vm.startPrank(owner);

        p2pSsvProxyFactory = new P2pSsvProxyFactory(feeDistributorFactory, referenceFeeDistributor);
        P2pSsvProxy referenceP2pSsvProxy = new P2pSsvProxy(address(p2pSsvProxyFactory));
        p2pSsvProxyFactory.setReferenceP2pSsvProxy(address(referenceP2pSsvProxy));

        address[] memory allowedSsvOperatorOwners = new address[](4);
        allowedSsvOperatorOwners[0] = address(0x7bb11BE268088B000eD4B1b94014D40371A3a7d3);
        allowedSsvOperatorOwners[1] = address(0x382f6FF5B9a29FcF1Dd2bf8B86C3234Dc7ed2Df6);
        allowedSsvOperatorOwners[2] = address(0x262B0b1Dca4998BF8dbdF83b0cf63C2dC1d74F33);
        allowedSsvOperatorOwners[3] = address(0xE5Bb5322A34e831a77bF06a25D13a0bE9B0b9B30);
        p2pSsvProxyFactory.setAllowedSsvOperatorOwners(allowedSsvOperatorOwners);

        IChangeOperator(address(feeDistributorFactory)).changeOperator(address(p2pSsvProxyFactory));

        p2pSsvProxyFactory.setSsvOperatorIds([uint64(326), 315,0,0,0,0,0,0], allowedSsvOperatorOwners[0]);
        p2pSsvProxyFactory.setSsvOperatorIds([uint64(236), 0,0,0,0,0,0,0], allowedSsvOperatorOwners[1]);
        p2pSsvProxyFactory.setSsvOperatorIds([uint64(306), 0,0,0,0,0,0,0], allowedSsvOperatorOwners[2]);
        p2pSsvProxyFactory.setSsvOperatorIds([uint64(400), 0,0,0,0,0,0,0], allowedSsvOperatorOwners[3]);

        p2pSsvProxyFactory.setSsvPerEthExchangeRateDividedByWei(7539000000000000);
        p2pSsvProxyFactory.setMaxSsvTokenAmountPerValidator(30 ether);

        vm.stopPrank();

        deal(address(ssvToken), address(p2pSsvProxyFactory), 50000 ether);
    }

    function getSnapshot(uint64 operatorId) private view returns(bytes32 snapshot) {
        uint256 p = uint256(keccak256("ssv.network.storage.main")) + 5;
        bytes32 slot1 = bytes32(uint256(keccak256(abi.encode(uint256(operatorId), p))) + 2);
        snapshot = vm.load(ssvNetworkAddress, slot1);
    }

    function getSsvSlot0() private view returns(bytes32 ssvSlot0) {
        bytes32 slot = bytes32(uint256(keccak256("ssv.network.storage.protocol")) - 1);
        ssvSlot0 = vm.load(ssvNetworkAddress, slot);
    }

    function getOperatorFee(uint64 operatorId) private view returns(uint256) {
        return ssvNetworkViews.getOperatorFee(operatorId);
    }

    function getSsvPayload1() private view returns(SsvPayload memory) {
        SsvOperator[] memory ssvOperators = new SsvOperator[](4);

        ssvOperators[0].owner = 0x382f6FF5B9a29FcF1Dd2bf8B86C3234Dc7ed2Df6;
        ssvOperators[0].id = 236;
        ssvOperators[0].snapshot = getSnapshot(236);
        ssvOperators[0].fee = getOperatorFee(236);

        ssvOperators[1].owner = 0x262B0b1Dca4998BF8dbdF83b0cf63C2dC1d74F33;
        ssvOperators[1].id = 306;
        ssvOperators[1].snapshot = getSnapshot(306);
        ssvOperators[1].fee = getOperatorFee(306);

        ssvOperators[2].owner = 0x7bb11BE268088B000eD4B1b94014D40371A3a7d3;
        ssvOperators[2].id = 315;
        ssvOperators[2].snapshot = getSnapshot(315);
        ssvOperators[2].fee = getOperatorFee(315);

        ssvOperators[3].owner = 0xE5Bb5322A34e831a77bF06a25D13a0bE9B0b9B30;
        ssvOperators[3].id = 400;
        ssvOperators[3].snapshot = getSnapshot(400);
        ssvOperators[3].fee = getOperatorFee(400);

        SsvValidator[] memory ssvValidators = new SsvValidator[](5);
//        ssvValidators[0].pubkey = bytes(hex'');
//        ssvValidators[0].sharesData = bytes(hex'');
//
//        ssvValidators[1].pubkey = bytes(hex'');
//        ssvValidators[1].sharesData = bytes(hex'');
//
//        ssvValidators[2].pubkey = bytes(hex'');
//        ssvValidators[2].sharesData = bytes(hex'');
//
//        ssvValidators[3].pubkey = bytes(hex'');
//        ssvValidators[3].sharesData = bytes(hex'');
//
//        ssvValidators[4].pubkey = bytes(hex'');
//        ssvValidators[4].sharesData = bytes(hex'');

        ISSVClusters.Cluster memory cluster = ISSVClusters.Cluster({
            validatorCount: 0,
            networkFeeIndex: 0,
            index: 0,
            active: true,
            balance: 0
        });

        return SsvPayload({
            ssvOperators:ssvOperators,
            ssvValidators:ssvValidators,
            cluster:cluster,
            tokenAmount:105102853212500000000,
            ssvSlot0: getSsvSlot0()
        });
    }

    function getDepositData1() private pure returns(DepositData memory) {
        bytes[] memory signatures = new bytes[](5);
        signatures[0] = bytes(hex'b30e5adc7e414df9895082fc262142f4f238e768f76937a79c34dfae4417a44c9271d81118a97d933d033c7fa52f91f00cf52c016dd493eccfc694ab708e9c33b289da7c4c4d2d1357b89340bbaf7256b50cf69e6c8a18db37dc24eafe5b7c26');
        signatures[1] = bytes(hex'a4407a0a3675c31807d029b71916120880f3500c5373c2c0ab604bd7fcd1c4548aebf3f7ac3a1d8d3935dc68b088c2a1195456f2e52244cfa07657aa53e28a77d54b5399a5dfca1246b2292d1bdcbfb523e5423304fc88ca587d3f986e660f2b');
        signatures[2] = bytes(hex'aad460f178be421f88a28293f27e4eba3b72e4be18d0803dcba581de735c950f4bfcfc431f6e8bf8e46a8bb7bae303ab12bba13862d66256807f08960677ab018d352849e7e580c99b05ffcb1ff7ec7a9d09bdd055a69d16ea80c533a4e5f0a2');
        signatures[3] = bytes(hex'93a3bd7abe123e171b41e5dcdd3ba7d040e3d1d69e41ed3cf67c1215fcca14b2ffb6bd603021bed758a7d67aa323c264180c92b13d063e12f6d6911ebc24e932566c01c87dacea02f1571369680b5645ec10a9b44fe51cc147aa775837dd91b2');
        signatures[4] = bytes(hex'b624037a0899714bb07d0673caefdec5a16535900f72d9d457994600434b19917437fbd67c7e4ff17860bdbf7b57657a09eb2cae3bb1fbf59a3bf25e8aa2b27ba066b41b1122fe5741523fe62a6682906e4ecd3c2da281452eb38fbbf0d66083');

        bytes32[] memory depositDataRoots = new bytes32[](5);
        depositDataRoots[0] = bytes32(hex'b91266d5b4e92690874f3815ea7b7b8bf0d72f6fb9819c7a4c6b5151bf15ce88');
        depositDataRoots[1] = bytes32(hex'3f751c3138d9da913371cd993991e3392eadebb815563bac82583bc357b73292');
        depositDataRoots[2] = bytes32(hex'89d95e435cb1535044ff888a3bcbf49ba4a950667def6dff3032e6a9e0655efd');
        depositDataRoots[3] = bytes32(hex'2db2efe5d6e8bdf6e95cc61c21b5b0295fa77ee0589dacbf830e7f68cfe9db8f');
        depositDataRoots[4] = bytes32(hex'2b86e89e1cdace0d21853457ac6b958a348c0ac6e94b2ae5d8c85873e8ec684d');

        return DepositData({
            signatures: signatures,
            depositDataRoots: depositDataRoots
        });
    }

    function getSsvPayload2() private view returns(SsvPayload memory) {
        SsvOperator[] memory ssvOperators = new SsvOperator[](4);

        ssvOperators[0].owner = 0x9d4D2d2dd7F11953535691786690610512E26b6C;
        ssvOperators[0].id = 1;
        ssvOperators[0].snapshot = getSnapshot(1);
        ssvOperators[0].fee = 956600000000;

        ssvOperators[1].owner = 0x25916caa0dB559bC7F21850cfE678dc9f273A8D7;
        ssvOperators[1].id = 5;
        ssvOperators[1].snapshot = getSnapshot(5);
        ssvOperators[1].fee = 382640000000;

        ssvOperators[2].owner = 0x28C48B0f9DA0aCfB1CA2910Aec9f0cc2e4F19561;
        ssvOperators[2].id = 7;
        ssvOperators[2].snapshot = getSnapshot(7);
        ssvOperators[2].fee = 382640000000;

        ssvOperators[3].owner = 0xf8D307BC22158C8B1852881da9A7DBd97Dfd7Df3;
        ssvOperators[3].id = 10;
        ssvOperators[3].snapshot = getSnapshot(10);
        ssvOperators[3].fee = 1913210000000;

        SsvValidator[] memory ssvValidators = new SsvValidator[](2);
        ssvValidators[0].pubkey = bytes(hex'92269be7b88c417f46aafd18943783990df0952c9858bd3147815e31f48d1be5f559387b696231f98fcc5ca2b3ff354e');
        ssvValidators[0].sharesData = bytes(hex'99b88e1eca1cf575cb1a677bfdc4876f6c5bedd1118c2ed8357aeb2e2ee2fdbb0eb216ad2540fdd6ee913e2c381b307b196320ac8414ef0b0d555fe6661579d59a4287090db18e0db509c23a1919f396b0ccb04f82c72bc88ce17c6fac6bc309a5b072ed1e69cdb407956c197df15594f2e9855931f11871239b4d25e44f518fddc9afd1d869454615a0fa2a81c9243c8ce92f451cb47b0b31040afe31af27de31015b10128f6ff3ca9ebce5ac75c6986fb0190bbbbbf92f0183bcdbb9ccd8f4aedc30faea71209afa8c7b383bf62489e036b819a652bcc494c620e463f1d5f796f794e7a96bd165c5738babe950dc1f9755581f9c50650949717f16a6b92228067eabfdc5b2ea77d77c8e3a26cfaa917bd54700f86b4566c266e9b8a0230836323a71f5f55999450d707bccc09a3a9a45a85f8cccaafcf55e3eb84df3f0b8d6af78f49031fdbca7adafc929ad097f0546e33a9b5ee7df80d65cb60e2c45342967a6f869565029ac2e5b83e8b9607e4193ad801a95ee14fac0791aab62d422e66afa52bb0f7ac829fd774ad45e07cb4415b9b5a4d67ed5588533a659d0da23903b9f215eeb1cf0febca0d0f7809dd94a9047bc19b150bf4602a38131565800557c8de10153ee1cb2cb38e72c834017abf90601b8c17a04b012f0713e929aa5ae8c35661f667c9508b89085801fe34bb7ee3d76b7d43cdfba20222dd3ea0bc55354bf34e8ae21b6c813955429ab65be266375e427d377f5306a9713a2a90b12bb23a310f3a1bb6d9d448921142e62fae30ec974a1c7d873e902c7afe335c7eaf7aa4de4bf958af617f230f220f8b2630fcfb1d32300e92a0691d3abbb2edf3e3bdd633de6d09c748c6506a64c93a18b2f9f30cba96261d88c1ba2673e85530fea53fd5962d7cd9c655477adc417c052ec88429ff241c63af8c4ae54c90a0b16363f3f314ecbde0adc3a72f358f76ec5f7dd801c4b9de0d6fdaced1da5f9421eb8ae964c7f0f1587fb01bfe863f05e04dd1b809c604850b8fb7e910bbd05a8e9dc87fc1358fb3a22f9d8ec416f80c6f3f5b8de75dc036b4e1303ce0598f15c6822dff40ae99f376b21593a32a5cc74694a26a90cffef496a4e38e86156e892f8369f7ad55e8b89d341d94933a9b0ca74a47bf34462f752c1f72dfdf91764c38cb5004afc51d9fe8169ec75af3cdd560b526e724d966b3e48a6e1803ac31dda18f7fc86921e21d4554963fc4a9894e283f16d6277f2c9a5b9ee33a3e7ab307c6187f06db3a594bd9830ec7506ca9f9cbb04a6a6449553a8d8dc6dcafd0bfbabace53a5fc8774167885a2aadc3b5e03e26a3be0940daed402184587bce40addd9873fbf097531357949376b3ea56c7497108e5f44b6f8d3242414283f0123a97689ff8d0bf864385a8f090f1a8bb1d3a5e822cc2bf1215dbe023d4c20de39f15799a985e2d040ced0767fb05d1887a7fc773a723e7f7564e4efa3062e761adee463a77a0a40ea691758e8f722ac1261ee3dc8ae4cc775305ab94d0f0c4c1d846c18cbf5e481618fc569a984b395f7b1307c8cf11468504cc1c5e3aeb075a7111dfa69c5dde491ea9edffb01adc78a9e15e8403722aaf19e0a2902826fc8ab5b13117163b7d45f40eb8707b882b096d2a567031d0eb36d67cd0d2201f7fcbb73f73258463e39e9e088756f66ff4d6d95819cd9915cf56bb39724c0f684d52d69ff6e63f3a6b46434e35db605afb91ba18d6022ebc3494e356cc7eaf0fda465e3cf76a60d8b5596f1e40a11123b011a3bc2643e6a2f1798e958351756fc652bbabb817ce6d146d4783efea51206241e6377e1d4e46a96ff9ec87614cf0e1e09ea1cc4e');

        ssvValidators[1].pubkey = bytes(hex'a413b93c25f77d27c5edab2b131d06bc90215c3eb2761309fdac35b0c76e12dccf45788a7ca0228b591cafb8626ab01a');
        ssvValidators[1].sharesData = bytes(hex'80207acdc7e6be7cd4e6479c3d8ad8439222da050260914a537cba09e8a26c33a6e757be3d3c8e75ca4905622f06ca631121516894135f065ae11b97fe901a5e2337a7309efdd62c320e3d3b25b4c8f6ad2812a7af56839f8d22c6e1fca86459ae20b38d7ccb90d2442bd760ca3867b0fdbed05c9a197045bbfae01d2325b42958db1a8d6a0903ebba114a594aa154b59523875c79ace4d0d360c69f5ab3020a24f549a7aa7b8c9fcd6e849b03976ee493b9e74a76aec5bf0c5dec86a91f42cfae2453819ec6b5e0887c7073ff45479a284593379d0a3e05d4f03b0014032a2a9fdb5d4670424138c7189fe4425daf718afd44d587a0fdfd3700dbdc0777e095b0bb5ef354f7dd3f6049a5bfe60156628378446c95c25282d6fe11fea1f072f1a6e50bd9698267998993a249633862a74cd2388c505120dbdc9b173ec3feaffc8009ca437ae1635dd58a3d683e110f24bdf6a5fe8ef4c74e2dc515a57b5ed5c420c80d0598019c273fa6d54a82802a477b2774aa6e3be20a7ada47898a426b1d5ad76508f734f3577911e8785203a310d9b41900c8406297a58c5a3a6627843a8e2f7b8770376a8c16f226668e98032445fdc11589cf7d97b09521f6459ea470305e464157084458bc84c9aa5624c9fd68d730a0aeb765b05b2496adcdaefea50460e73d788515a00d883cbd42cab486cc5ed4e6a43d032fc33a11041da6fd0ef0a1e11dec6a17381caf2c3b4f1f7414e0dd8d2c259c4f1c2aec04f6f40f7291334ac9b89d9304a7daef9ceea5964e99ffb0c4f87a92774470f410bc11780e9b25c1a1614d7ee982a5aa690a49fc86ec92b9875812c68969264ebca7e5c4d51211665fb862500521fcad571467a04387664ea610918f1f74dbe6d0034d48036e6faa0678ea64e17121a83b1a27a2f97482bacc7f7a1f44365f08009947cca2e1ee18606d824d1df859988e3a718fb5e00370d924123de285ecca75bbf31b543c3ebd5a55cfbb3fb49528d25322c7fc9becd61d07291bdab488a7b8c660e22ea44e829a6043caeb50261f06c249182b0aacca28c61e73f34fdd2888a748e1951bbdf55557f9b1f5ab036c5f3de4eb816b750981f3783e581e8a9a15c915cbd6302d44c140121f6ab61bbd186f5cd4fbdf0dc7f80f44ea192de2902fbfa12fe0aef51d80874c1b7fc623f1fbb6b3c278df74c7262570da36d5cf4ba7e81b374344c201b49ddabb53692b7e5e9bc77e0dc37907e641f449fa9c42c6e914ffd1eea36ff0c77cdcc98ba84714d66c5358d1709af13551ec184d32c9a2edde8a8d459f898b494430d74de1be67330359c4399e46c5f5fe5082881396c81fb65f13a1adf31a934d70911581302798481e9b4a25e0cdaa19cc20910e78f4b36cf9e2b75cef8cfb8481583926f940d32c38f8c900ce3ca3577e3f9261a06efca76f53a12be3b255071f9ceafd06b30ef5044b7c81f0484e352a2661ae9f7780c9d5c55589697b037e5ea7da1d84a34fa2996f9a56b9f96bc1410b450b22c49558b5c39c38ac3b0210cfa1ef32c9184462fd6e1da87646cb56c66e6978a0e9574624c43b27909cd4fdb3d30f57b05cd55e766d46755596931d2b371d5dbbfc107a1534a270d0f01d5b2e291efb323f1d09930eecba5a83241d6c4dc6643fc27bbd950c6d95d42fd2c6c22105f9abf8f7239119b8a5b574d19e12ee217dbc3f29a022a3267df20f24095d51e3101df412225905ffd2af164d9e92b0ced825bae3393876c4b39c5d020964790a8617464fbc0f30d6e1d6267ac7d9a1d44e3573d41ac10a61c9c4cbdb052a71f0be93d4e6a5b9da6526a9ac960740432648e76fbe0b1e9e9a4f');

        ISSVClusters.Cluster memory cluster = ISSVClusters.Cluster({
            validatorCount: 5,
            networkFeeIndex: 0,
            index: 410620802294,
            active: true,
            balance: 105102853212500000000
        });

        return SsvPayload({
            ssvOperators:ssvOperators,
            ssvValidators:ssvValidators,
            cluster:cluster,
            tokenAmount:42041141285000000000,
            ssvSlot0: getSsvSlot0()
        });
    }

    function getDepositData2() private pure returns(DepositData memory) {
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = bytes(hex'8c00eea680eadac2f426cd3809ab3177ab4b25c3f97dd80fc4ba0c055ff8d60e73381de456cf8b8184d9af2a15bb318a144cd0b0c261f462b58e61bea15e1fb9ff67058950ac0eb2e430feca3915c2c49d36b83beb3f7ca23141b5ebd5cf12f0');
        signatures[1] = bytes(hex'8a28e64df753ed8e4785db087e4c6b7476ab4d11d711674b2d6398fb82dde8417e7b5db8ccf4383e891da8bdc167982f17dc7712a3b27c6b57d90b08af884486d743ffd904575561a29960f6ee47cda70a606b461b8dc475d191bcbab2af8662');

        bytes32[] memory depositDataRoots = new bytes32[](2);
        depositDataRoots[0] = bytes32(hex'20187410c9727808d2eafe0bea417c04c65917236ed424f21c8daa1f2b494f98');
        depositDataRoots[1] = bytes32(hex'8c75013ba6f48bd1c635c25d8e6e1f3ca04a8f30ae77d91dc53f49df518de687');

        return DepositData({
            signatures: signatures,
            depositDataRoots: depositDataRoots
        });
    }

    function test_temp_Holesky() public {
        console.log("test_temp_Holesky started");

        bytes[] memory publicKeys = new bytes[](2);
        publicKeys[0] = bytes(hex'b3e64234bc0973fa5c64998e9d8d177970b933f94b606353f21d262be2525cb7f2f0061c3c31587b1ecdc1dde3e50e2e');
        publicKeys[1] = bytes(hex'91e94ccfa337a7e4e835a41a6bc88344c56d180b7ab8fcd2ae9a0bca14d866498539b9103642bbb2067b8cd87c672094');

        uint64[] memory operatorIds = new uint64[](4);
        operatorIds[0] = 111;
        operatorIds[1] = 119;
        operatorIds[2] = 139;
        operatorIds[3] = 252;

        bytes[] memory sharesData = new bytes[](2);
        sharesData[0] = bytes(hex'81f87077f39fa61f9f9918585596a50bdc2be639cc94059a61a9e4a27f0c37e5abecaed565df2ac525a4308bcc2cd73106b4de17fb545b9b6b1c5025a958ac4aed43356ee9901e130deb646cc7988224ca7c168b0eb0a205d59da7208b61fab3aefd2e44d24943c432a5b82b39f3a85b6300dfeb8dc8ca3acf09fe0027906a8d1f1666fd928391c747d4a7243f61d42180a6769bc60a9461f8d6542104dd2bbd16948e9d970d520fa9c439e253e0b13d87e0d3987f905fd1481e3693fbb4232a96b36a00525e7e1b7ef5462ff263f9b88ac3f92f2f924c5b62e9d64fb04636791274b4168f3fb7cb3d7de642dbfd3a3aac88f266d63c0b7da7506ba06181deaabc0fbc6952d354043925c8386e52cd8468f248081abe2e2bd742130bcb55c0ba4c2d356613632ffc99632e46c283b6cbdecd2860d55a803b32d262637df223eb7c8860f80fd948a8e8a1294f4994c0593e66f21bd1f70d4edd32e577dc5e4f9abffe390c50cf788f1d980a93b0798dd27dabb62c9db6b64e13797b84057cff80a12ebb0b04e4a637a379a13d62a5591475be676141a058dd78e8ce239e11b5dac66848d16350ab988164574d6f6e9af26507cd0068ab75a33814dd3f7d615aac9a49f1084b5c5691110fb49d8e2ed9382ef0a98920997960ee4dacf2bec2329789c13e3c8a6a8cadf67718380a8c0da3ae383f303775412e7ce19a09504cdf42b5000cbbe3f5eb302b7d363c1c0bc5cc74cb8f7e4cc74246968bea0480e149ec8a6827cb6aa670941534961681d3cf99530e9371a5b8854256a207b29324f288cef58cc799d4a7f118e0ba193258b1aa5c76424a456145386d86a66264c8934ca2eaa8b6967472cba647662477becc1db9513601a1ac5db2b089842b7930e798b1d627922bad9f7b51b56e29aa6e23ebd5d5e77e0d5bbe7a081789d108c98f539f79af3bb829039fc8ffb38f586f03a90e4ec8abf54dee9b43afae0332376144c54676eb24aedf3197b0ef34e62c258b86f1ee119216a2765522e82eb2dd056e844739115d69bf0ccd575080d0274aff8211deb7b9783d361828d21a9bd27e656fdff500740c1f6c05d266649c198deeec9f78e763045167560bbd0f8c917fc5027fe3b6e2d258c137fc331c884e2cedd5f6ce3378c416cb721d0503dbc39c707e2e18f6cafd50d12ea6ca48eee99960f43f9a5a07ac471ec5364e394f2eafe92685778cbd03047e31e9780beb0f3422ba9a4209f1ea7cd670c4886418a749df42372cd042fb90fc983eaa75e623421bb646c14a84e16743409123e16e3058c72344a00028848c571d44d78047c8ef2320ef26d7dbd59a2c0e90a4b6cf53210190436fed04d39581fab8717b61471dc96f52ced2d440827a3c3e67080837d26f84dd05ef54e195cf3eb0c224ac586f7437ac84e609bc5bf666f8de0d04c8dd001cb131a1471f47473bba8b8b68c3df7361974d1fb56eb352c63d137d5e125eece1c5f66d9bf57f667c2b577a361f8d216c07f0594c721ef52138100a8d442a2e1ecb98e6a7bff8b0cc1c598d33b8e498aa9ab0dc6e06f82d7dad054aba6361ddc7b1333c99174d86de071e047468926d8570e27b59b55ef298cc43bf9d2a7c792cd0c5838709252d4efb5f63b6258f7970442a8065a07880483d9d3264688c73455162354cffef26f2145ca50246a8bea50f1da097d9c91865f875826b7148f97ddd1bbabe2fde50b1ca09200a55c7ae2cb755580ae745148255354ac3279b97714ca5f3ac624a79f667bd9cf315010595a09feaa2b71353bf4b51f0cae0ca5fa170ae735abfa7fda603c428b711ace6379e63b7d1b2cd8f824c28a3314b30a2');
        sharesData[1] = bytes(hex'a0be175c52347eabb0d6078909ee45ea1fec64fdf8295d50cecd5346d7ad1b54fe97ddb7488548a77f1ac55e8e1e9e51125d0a5eef35090b7926bb5c082be7de8074747976d05dd2971dbaabdbe6da7759cf586296f69bd323aea43d8cca64189501e2aaf2933b384af5737e1370c18461ce7f07d1b272c0fa308837e5075dbb364906ef857a5d200584101dfc4c791884f89a19fe7e643cd569f0716b32f3784b0582b6d3c5317355b7336e8e65a14e8a809fb4437a54ecaa5fcd174a6412fba43fee764e7668945675d2541d2e2d9922fa768c3cf4cc2dd1fa57a64fe23e578e2b5a2f99b9ee22d82f00a84f9dec698a4f444b5f0b0c6dcc2afa01015721cad360e3a601840d27d75bca638a9d3cf9bf1032bf94d26eaf6d1205a4353614fac10b11c984a7b69825c99903b88a6f2e1ed051bef68e6f2b1fa77e96d03c1ff7ac7f3dbf285a7be79274b31e128688e60a3959431dee9f7c08ba871e306dbb75d45153b877665a022d8c9fac0d65401e6ae163ec89d318f9056340cae2ca3430c8763d07d6f01efd5c2546da1db99c5d55fc44fc80827aabf8241f12056e5a57876f00f219c05d63425561e4135fa69cef77fd10d82bcefdeb7f7af0e447d3bbbc939efa0c9ad29b7730d18c848f05d73b3231a277ea5a2ad317a3ffe337616c5c7931fead9a9c169006b4797304e8e985fe4f5068c4d85f9a283c8eec7f2a2eb453030d6cc6b2fdfb3b2ab7a10f14379ed8450eab5db73b1ec299a198e62723b5e56db90fe7643e42a45095839f0198b5774ca203ebb8283100af35d213e3c65365dc4212e5a3137275c5889ce8a490bb0d229f532a2fe166d37c470c492f20779df30daac0aca540c4bf15b557ecb78f5ca5204909b4b9b6c3517f7c4afe64bb55bbbed33cd3594800d039950748982db6ac770e92b481d1d2be2e161c590eec4367e263c2e68dde547bccb082179b408dc22aa411886ddedc6e1f424a97ac1062cde66c7b3dd64c8f4a986f7200761201ac72642236a931752ef6c6a53082a3cb634bab3d91eb6428cc7c3d1ba0c37c8c2170a90e2b62b22f2c386b7ef769fdd88b50e94170ddb4d62159c0dc28e7d1c6897aebdf6df2a3d3affe967db7494a53a151de3dcf28d16abf9a9741706750aa58c52dea93c1ee966c78854c2d91f0a40fee63097067846f547e990474688a77ee0e94f400a436077791cf031a708785c46b00ac05e680fb0f068eeb54fa1269a28d2024b456f06c4cfbd12f3313ea1036bbbc6b6928f2c8ea8b4c10baf1621c25e12851d67e9e6386abe8518a3918046e919eabd108efcecb924c279fb7f1f481da444ec83faa4aee25809f4cd661671701fc7c4da2a716ce57e6e167e2e363094f98a4707693987fc4a256fbee9ffb6edc030d157442866d609aeb6f6adf55ec0295f0d913d4829b1158b2b1dcf5a726d27920a6a78fd1f9396b66e7e1a96a2f768064dec4eabb7a1f7bccb5ae89619dd456ada9351f8b24caf0a470c8d0c6bb7f86c66176a37fd46b257b5b4d9673ef9e101e3219d0ee496c351fe7425e96158f31a02a07633c494f8500b68a99eccdac4315174b6f76788ff2a5708aa944b0bdb33b17b06ed8fd0b16c1bdec1d0ddf3b390158405e1b845f49ceffbee517ab8c3cf7dcb6c2cb243cf9d423138f125c7137741ce8f2dbef405795987b806ff6624c98ae2fe3eb628158bfe10c2225ad6f481dd9961d8432c905f6136c3463a955f6afc34fab9c2a400a7c76f30c9a0e9e58316695003d77b212caf996153577bb106f0a06efecccb5e3d70f6d055abb7abbe532d8779b12d86257aa3fc517f4807a008f392ae9166afa03ec93');

        uint256 amount = 7499943944000000000;
        ISSVClusters.Cluster memory cluster = ISSVClusters.Cluster({
            validatorCount: 0,
            networkFeeIndex: 0,
            index: 0,
            active: true,
            balance: 0
        });

        vm.startPrank(0xB2EE025B1d129c61E77223bAb42fc65b29B16243);// 0x2BDBcfda5E85fD7e2303A9B338Dc01cCB42cb8E5);
        ISSVClusters(0x38A4794cCEd47d3baf7370CcC43B560D3a1beEFA).bulkRegisterValidator(
            publicKeys,
            operatorIds,
            sharesData,
            amount,
            cluster
        );

        console.log("test_temp_Holesky finished");
    }

    function test_depositEthAndRegisterValidators_Holesky() public {
        console.log("test_depositEthAndRegisterValidators_Holesky started");

        FeeRecipient memory clientConfig = FeeRecipient({
            recipient: client,
            basisPoints: 9500
        });
        FeeRecipient memory referrerConfig = FeeRecipient({
            recipient: payable(address(0)),
            basisPoints: 0
        });

        vm.deal(owner, 1000 ether);
        vm.startPrank(owner);

        p2pSsvProxyFactory.depositEthAndRegisterValidators{value: 160 ether}(
            getDepositData1(),
            address(0x548D1cA3470Cf9Daa1Ea6b4eF82A382cc3e24c4f),
            getSsvPayload1(),
            clientConfig,
            referrerConfig
        );

        vm.stopPrank();

        vm.roll(9962945);

        vm.startPrank(owner);

        p2pSsvProxyFactory.depositEthAndRegisterValidators{value: 64 ether}(
            getDepositData2(),
            address(0x548D1cA3470Cf9Daa1Ea6b4eF82A382cc3e24c4f),
            getSsvPayload2(),
            clientConfig,
            referrerConfig
        );

        vm.stopPrank();

        console.log("test_depositEthAndRegisterValidators_Holesky finsihed");
    }

    function test_registerValidators() public {
        console.log("test_registerValidators started");

        FeeRecipient memory clientConfig = FeeRecipient({
            recipient: client,
            basisPoints: 9500
        });
        FeeRecipient memory referrerConfig = FeeRecipient({
            recipient: payable(address(0)),
            basisPoints: 0
        });

        vm.startPrank(owner);
        p2pSsvProxyFactory.setSsvPerEthExchangeRateDividedByWei(7539000000000000);
        vm.stopPrank();

        SsvPayload memory ssvPayload1 = getSsvPayload1();

        vm.deal(owner, 1000 ether);
        vm.startPrank(owner);

        uint256 neededEth = p2pSsvProxyFactory.getNeededAmountOfEtherToCoverSsvFees(ssvPayload1.tokenAmount);

        p2pSsvProxyFactory.registerValidators{value: neededEth}(
            ssvPayload1,
            clientConfig,
            referrerConfig
        );

        vm.stopPrank();

        console.log("test_registerValidators finsihed");
    }
}
