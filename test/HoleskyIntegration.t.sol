// SPDX-FileCopyrightText: 2023 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console.sol";
import "forge-std/console2.sol";

import "../src/interfaces/ssv/ISSVClusters.sol";
import "../src/p2pSsvProxyFactory/P2pSsvProxyFactory.sol";
import "../src/structs/P2pStructs.sol";
import "../src/mocks/IChangeOperator.sol";

contract HoleskyIntegration is Test {
    address public constant owner = 0x000000005504F0f5CF39b1eD609B892d23028E57;
    IERC20 public constant ssvToken = IERC20(0xad45A78180961079BFaeEe349704F411dfF947C6);
    address public constant ssvNetworkAddress = 0x38A4794cCEd47d3baf7370CcC43B560D3a1beEFA;
    P2pSsvProxyFactory public p2pSsvProxyFactory;
    address payable public constant client = payable(address(0x548D1cA3470Cf9Daa1Ea6b4eF82A382cc3e24c4f));

    function setUp() public {
        vm.createSelectFork("holesky", 383525);

        address feeDistributorFactory = address(0xAF01ac4acE27a5d33b68B72aABa31C2fE4fb169C);
        address referenceFeeDistributor = address(0x93C357c42d652E615948c013213D9e8822Ab1183);

        vm.startPrank(owner);

        p2pSsvProxyFactory = new P2pSsvProxyFactory(feeDistributorFactory, referenceFeeDistributor);
        P2pSsvProxy referenceP2pSsvProxy = new P2pSsvProxy(address(p2pSsvProxyFactory));
        p2pSsvProxyFactory.setReferenceP2pSsvProxy(address(referenceP2pSsvProxy));

        address[] memory allowedSsvOperatorOwners = new address[](4);
        allowedSsvOperatorOwners[0] = address(0x9d4D2d2dd7F11953535691786690610512E26b6C);
        allowedSsvOperatorOwners[1] = address(0x25916caa0dB559bC7F21850cfE678dc9f273A8D7);
        allowedSsvOperatorOwners[2] = address(0x28C48B0f9DA0aCfB1CA2910Aec9f0cc2e4F19561);
        allowedSsvOperatorOwners[3] = address(0xf8D307BC22158C8B1852881da9A7DBd97Dfd7Df3);
        p2pSsvProxyFactory.setAllowedSsvOperatorOwners(allowedSsvOperatorOwners);

        IChangeOperator(address(feeDistributorFactory)).changeOperator(address(p2pSsvProxyFactory));

        p2pSsvProxyFactory.setSsvOperatorIds([uint64(1), 0,0,0,0,0,0,0], allowedSsvOperatorOwners[0]);
        p2pSsvProxyFactory.setSsvOperatorIds([uint64(5), 0,0,0,0,0,0,0], allowedSsvOperatorOwners[1]);
        p2pSsvProxyFactory.setSsvOperatorIds([uint64(7), 0,0,0,0,0,0,0], allowedSsvOperatorOwners[2]);
        p2pSsvProxyFactory.setSsvOperatorIds([uint64(10), 0,0,0,0,0,0,0], allowedSsvOperatorOwners[3]);

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

    function getSsvPayload1() private view returns(SsvPayload memory) {
        SsvOperator[] memory ssvOperators = new SsvOperator[](4);

        ssvOperators[0].owner = 0x9d4D2d2dd7F11953535691786690610512E26b6C;
        ssvOperators[0].id = 1;
        ssvOperators[0].snapshot = getSnapshot(1);
        ssvOperators[0].fee = 956600000000;

        console.logBytes32(ssvOperators[0].snapshot);

        ssvOperators[1].owner = 0x25916caa0dB559bC7F21850cfE678dc9f273A8D7;
        ssvOperators[1].id = 5;
        ssvOperators[1].snapshot = getSnapshot(5);
        ssvOperators[1].fee = 382640000000;

        console.logBytes32(ssvOperators[1].snapshot);

        ssvOperators[2].owner = 0x28C48B0f9DA0aCfB1CA2910Aec9f0cc2e4F19561;
        ssvOperators[2].id = 7;
        ssvOperators[2].snapshot = getSnapshot(7);
        ssvOperators[2].fee = 382640000000;

        console.logBytes32(ssvOperators[2].snapshot);

        ssvOperators[3].owner = 0xf8D307BC22158C8B1852881da9A7DBd97Dfd7Df3;
        ssvOperators[3].id = 10;
        ssvOperators[3].snapshot = getSnapshot(10);
        ssvOperators[3].fee = 1913210000000;

        console.logBytes32(ssvOperators[3].snapshot);

        SsvValidator[] memory ssvValidators = new SsvValidator[](5);
        ssvValidators[0].pubkey = bytes(hex'8ae430787d3cb55093dba32d4f5e7736c48d494121dc6ed5520182490b977af7ddc0ecc586296fc315f9553dd07c5486');
        ssvValidators[0].sharesData = bytes(hex'b9a1c7bb68516eda9a4c86bb85199264f87cf9d02dc984e1cac9ed0e6fbc6cedf81e712d1cec57c96679c19e5d63424a1108932010c26bcd46195b3358a1649813d1e4013445e3934491894d9b45a3c9404f7fa078af6d8ccaa3614cd54b67ceaf6a614ef60693ad6e04b9ba32f345b4b1b3024d763347e8f115088bd386c2312c917c8e194864e937284953957c2fd0b9ccf1b08058f27ef0e13a28af34dd5059f3e78fe70642acb0c097092dc246f82f88e509fd122d9f4a0fcf4408f7729cb9b5cae1b1e62b18868f173b7831a774196f1fce99a48285922a30b417c3c72829ccc49f470f2aab5080678840de4589ac2035c8f927eaba1d52a8a58e15af315b238db0b4f8507a56be8b4fd6ab21e41fa4a22f7ea177e6d1054db78d2f02a24ac8a21df83ec106a4a12a6334663bd8dd2be2f043c274522f7a02677fd1e728c98653b03cdae701096228712cd5b9f1c50a7accbd7eb716b428341042b5ec3d617e3c6432e61b4666f5ccdfec797f644d4a8fd265ebc09be0f2c6d8a9a174ff1de0bac804df57476f578c6d358411bbf57c4505cbb42fe81e7bcadcc49145e50f69c95ef598613ee468733313316ee0156f38be66af3971e034ddfc5ffcfd7a4e1765868dd114e12a8fe99942cde05e72329fe56346e2baf5f3fee98fba525d325e2b63e8029b6eeb4ade25b3ff2e52ed894c2c82e0b4d6defd4e2f6f445fa9ead388892523bcb2b25d99dace8d056547286778774c2c69f7b170544bcdca2c808d6eede096374cb0ecec549f0010428b05f4cd0d7acb6f7084f1ecd19004ab2fe199c5175ee88b55cc6b5ea7cca1ed02c1438b91c9be195b7ef5c7088fa83b9b39827a3b043380a404c9ce3c6b1d9f334a86a1e31bd3e5b519f87a63e0918b8253d4099261a86333d3805963ab1ae9d316cd254fd8f98e0d00c4c7272b38119a68131ad859ba052c475557a4e2acba7015ede2ae86738cde6f8d34416876ac61e824f4023faadfa9099674d48f740591e3e833a60f961867cd7535cb81d64554c32a1bf03543cbfcca50ad1ec9bab98e8d3fa8dd6aea26564893e8eae335a043ba713cb276b46e9edc9807028eaa45bacd6d9448fc25fb8ee4e87e8de809d756348e33949536f5223b8dca703f6547050988286f289a57f68e1b14d048535eb1bef90f4a47c06d894076597d0ee84144e3dd720162ba6f95321fce09d018800131f8b3b6f2976b679ba2c1b712fcc1ccc47f3689224c26520e6dd5f737403ee79759dbb1a60c6703015810f19c233fbf4e497bdb267b519ee64b1503d7f467be509589f3fc10f9eddc7880617222f10eba1e476f0574ae8633da6b1457f1952ed53c922c9ed1cd85d1280b755f3a666710a28413f97cb2432d4b13aa785222af82f7b493c8034ca024b572adf2f81c97f133600b4d5bafae49dda0abd3d52ae0c5381a85dcd627a4557f0c2d5c3d9cfec59fa2f53f8bb5e42d62ee18215d2e94b90e1309808b072d3ea1e6e2c009a580b58e6c173f66622750267163f2fb9453d142b2f6033d67592dec7bcdd3790ab8a65cfd96203138aabffbfda455b6b2c08a1c8f712fcede25d1f035f290d54ba8a59f878c7ee50e810708940b6a8e151b0ebb9d3143ff2b7956f2d5c818b208bbd0d2724152bf71eb25a1b1ec9569b238e2ef426b347c987c44ac10524404fa925dda471ed732f714f58ed01a0f91aec98e2eaa191d3c4e62af2e6ce179ca89edff72f31bd6c75789086e86cd2239acfd07cb5c059db1eb0d4961a1f0590949ab9617c2aa70a46d555c01a520cfb8db392ff6cd84a929af94b3762e054adef2ba8e5f29ceddd388e3a67a646b5aa0a2');

        ssvValidators[1].pubkey = bytes(hex'b87798a82ca43743b7b726bdad694c8c9b76b68023bde42cf97a0e4d0da7e3604d4b436b9db44ef5e56106626d95ef68');
        ssvValidators[1].sharesData = bytes(hex'9465cc513c3cc3002dd5da42e1dc20e0d7513d187d9dbf808769b87e4fe434b9d5311ae6e7d0d4488b9c5c7757d40b540a53c5f4bf9d0532668ae07209c78a661ed6656a6ae891c5e201b2a221aa2e7bc86b6131527d723caa866062e9b362878189a572e42de2a6bad527a1d0b648c8ecfe55089843cb044a174ed5d9711daa6dc3d006bc5e3a85f73351f08526d28d8c3404ffe29804c711485caf3d6991665ca5d9a62d089caa5061f9526f3af07fa4a1b80f75a11259c9902b5821ac86c3848eaa90ceaddb20e50127c721c64c492c99c581e0b2357ad3da4aae361876cc58a09db8581f4bbdf8e53461e3d43ad2b0cede5ae6c1265d0d485a22566b1a900063b0e3cfdda7eb58af90c1023c678f8cd3f4f6d5299ed579d2756aa46dfeda63bd43f63fc35c586d7f34f0084b1e0cc667ca2ca7072cac5ae99d7cc62a1f9d685a239352b5b7bdc49fc72861308ce4992fc4bd09fee5b1c1b8db75570f91fe0365556680fcd9e3168b9f3d40c69b26b6c7abb6b68081ee74a1123c853a7491d605f0c711ce45f334eabaa3d0772de8f453bcbf383161993db18b1694bf8dcc277e46cab7f79d7feca9bcaabaadb9b1a2f9378e23ba72d72cfe3495f4e9ed51c32509342d28bb6051d3bac445a5a5aee32ce1363d0a492273ed1b443e95ae2e858dcd150bf0cf68eb9aac94c8af6a4916274a22dd6cf8afb0fb1d15800d131d1ea8a50d9bc5f04cb3d1a7b319596416680742439b202a0fa601856ba3d41bc752ffd0fcc0a585b9e9092ee5f5e23c58f0d971108fd4408c12fb3d1c1abc77eb1ea3ad504d85722f9937494ae3b32cbb66c43b115bb9912a924ddb2723b1f67ca8642309c00fa74b9e78e45e2b361f77b6f9494931a9c00b994955498677ed9cf26a6c40bf066fc05389e17453c690349cc089aa6aa4d3f689e9ea191ecb3c901f8b288f18ade37aa754b78e875d701239b91baaaa7013d36e39ebe7ada2db522dabe91278ed8701439b3cdc0874078b152bb9934e5ac180e5089324590c26efdda2933fdfe5ad6ee3d3a23007a6695538f4249d4f776ca88e484861448de7608b32cf144fb56bf839d3fa2c1e1cb5bb459273c48b0cbf84c2a3b1eb24b8beee38c5cfeb12300d84f23a805d08e17d73ea4a79abdae59f514689f10ae28b45a188b7b0c6cca1ca510f6db0f4f8e2966d6b3cb5f057d5c0a0edb46334615e54bf50cac596ee0d0a20ff4b4dce64b488c35ae9dc2ed0ccbde9292b43fa4c3b9ae2de7a86e654c92d5c0ff201b5e52ce64fbe3db90540a4466ccc81f1831010b3022605ed91835e824d1fceb74b0475b6a22845c1f44dcca384d1a9bfea231db900afa6ec660f281bfa0a21b198fc1b5a2367c0036b4793ed18204d6180887589bf8c5e4e8102ac7d1d1901c67a7584c1c0ac27532ee5ec4ca1d2a08bd329d6d81a8124d6d70b8109f26b581989e3b1785643d41c7e2488e254607fb7ed2430ace30b74d4e2a3c4a7721a28a3d5635b57d2d08b92a902b18b6243a62248a6db0c5b026ac2a362e26426b9ea3971ef82ee4d5b683072041c3f6575866bd60edac3ae69f9b40c8b26264b593fc15a10f537df41b11632d0390e128ae3f982732c376c82998cb8a2729297a1fa44c4ef6d87541b1b3f3df622dc781addcd89df045e437e30cc08145e49d6667d690b22045756e0824c93bbfd3530f22b2956d842c011f2b9e06ee2b5c79769ec19a7cada0d4ee4e1c36b959ed85eb5e7b63a43068b312165ae462eec5f7fb4d5f6d26cffea6a825e40fa8ad2f07bde4707d9b21247e4f4fc990c533781780f5fd545011319a2d1f4ff8448751e1abf0641f716c9f31c');

        ssvValidators[2].pubkey = bytes(hex'a3e789d3b378c42a3c963ef549b739ca55d1cdc7211aa22ebf382e4e847ea23f12c5a5131aa835afe5743432b02df806');
        ssvValidators[2].sharesData = bytes(hex'a58c604c3eb29bc197121b458230d33e4f331fb34489a83691d8e2f5e964c18d4eb715302ae63c10843a064d2d4ac4700f895cfd38867a45fce648465f53341fdbfd84178fc6845f869b81b2edf94c848f7e63dc1edc0e3f1a3fde21a6116e808b84e7fcb3b73e4f3be18de7a19d8df34950d1ea066a91a27c8d9d75344f19a068687611a3ea8fef94448ad560f30c8ba21a098ac9e476819f5da5c7962bbdb2f72afe320698f727132f212c068222b995e651275d226fb3561e59fc47f9574ab1351035dc12fdbe3f0656c8bbff35ce7e44ef1a66a1f6698c327eef3e011f69427ae2213b7e9cc1f00d1c22e86c8d01aee97f7d3ca448f91e2d7fa262ca7cf35d7d4070e2710e6f60f73c08518f4bc9434fc7fa17d9865865c832cdfe4a1aaa82e9869de9f5afdc45e82132041076aa239fc7309198c4ef9b72d187b541eba49d5885b79895aa1fd6971eb08f80f60921ae6f40ae37223d27da6a4acbdd133360233942c8c90fae8edf72702afab2d9f2d7dc652d267db63f97a963aa57167eb7f8bdb658db7a3af070efb175fae5caff8fa831bacc6a74508bae8a281aaeec76bc1642a3bc208f5e3935a1f05afd3fa2dd7a4c9f94f72558c149999e5a519127d4b4e0ec6e8af685a09f615ff704a241cb68e58ddeb0bbbbf629b48aa5864b60cf35b898e86223cb01aa1c5c79653c7f818a382f570d79ba2d87dff2743ed543a8c8501b81c6f00157d37b0dd03fb747a710dab33e4075599133daaacf501991f03479dbfb20e2000cb0efccc193ed65a380a6c59822429f6823014de65c6a18cb7144f4cb573ab8cd8bc3d27fafb1c2421c2d75ede07c83a5d853f3ef0f2bdac045accee070a0cb51c2d2143f5a2cb35f7b4e366963bdb953f24e6c1a0290fbce9ed4cc2605c38862be408575f3d8e40bd7d2eea2fa5a418c958a5d3ab8b58832c0745d96bb68295ab5da28b92c08516d44a5fe4edd671eaa6d2db691c436ab5d8df46a394947fbe29cf95a0203a45c147b06d034d85c743ed20a9c45f26a1071a436c2b3adc1080f24e2c15cb2a650aa8ba339a40de40ea99460d4e678a1c26d919dbf9c8e0fba43979cb6d03100b1c79e446c0281786808c4d9acb5c41b5e739ac27d54caf00a172555da798fb526d062b50c200b9975f34af04c01c5c7c2f9aac73c57356b56bae457604b54d48210426d40ba2b7d1575465ab545748097a028d86c2fe2ec3213650cb46192e1a6ff5a0256eebd9d6182c9ecd2253dbd073143ecf884b21ce4c5421d70a8cac29fee22564a1b979b96031440cf5091f819ea3144189b73881cac087cf0ebb0307f725848406dc61906a9864ff14e15c9442d440edf7625f2fadf50800b8af80a803dee7906d7953c9fcda8ed4a85660f46ace16ede56e75a54571d1c104d48be73dc972ad0d278c2648006c445d9617f329965ab5ce0782b6e44e2eab4da8087b875c123aa8dbf81f9e361432da2767d6c1245a3a34b6bbac3f5c64ae9b4f8a064addbfb86be13fcbd9d44c50670dca5e240daf4073e7b2637f75a5a582fb3491ca91db54eeca36b5f1c07cd87629f891265e9a25b4bedeb93a491c3f0ee585d7aba48301a26be7a7fa8bc2188b8f50e070c25026d6c43233f0f332a2a708d0f2a50d00e6ead71d27d5fb3bfe8cc8cd776417b806232dbd56916aab29db106543e7d7d37c22587ef7853d61242717bb264cf7edb1502373acc80cdf508b713432c404bf77dd5e32e3ba4bb08de0a42fa99eba0b1ddf8c35ab926863ca2b061f7cecf564ac7a2eaf08225fbef3b6ad962781ece2e3a69666b9f37250b2e738664e193b4dcd4e888551683f34775e13872');

        ssvValidators[3].pubkey = bytes(hex'8171e4c04ea01ab1a84746527e33fdc739ad118946ba3f1cee356f3b35e9642304a7efffd1e4db4aa556ce333687ea11');
        ssvValidators[3].sharesData = bytes(hex'83eeca34b3ac3b6922d8bf8e403836e009181afaa12a7f958b77fc7e42fa1dbad7c525ebc00024594f39c8ea07775c0b0bd9b6505a4ef1170064f430052af5ab7595320c48e6a3afec3306fb6232b956990b37b11040bebdbdc1c08823fa9e4b8c5de413d3d9db2eccc0ce6e8f013bbe8608e9002be0a2e86361fa243f9cc0cf247da7eafb3bb38ae6edc7975ffe9e4eb18821265922f291f739704df9beb23e5224bad86cd0c85b3e3345cf445766312f6871d1a15d4975cb888680255728b083ea096621ab4c96797768576ff2bf12925d738b0203cebac4691cd106c8771e425910950f970526ebf6077068e29a7aaac311a3b2c6cfbe3d909b07dc0ddbde42ff767da405d8e59263e849d91695202dbc2818ce0d597b06d472a9b524fa2f49f6c45a2a5cc0d5a095f4d0bef9ce39b6b6f650d5fc8531779d8497ccd3c0ed3166c4744b2f281fada05cfd7720e54ab3b45507567c170c138ad39014c7b927d5d87ffeb5a176b4ad94a1ceae3204c2a571616b99571002a94ac5b8935fca07ec46b0bb22a975df4faea9a76a3be36b6f495a36af1d30358826ad7b0fa9897a3a128e553a8ff36765130d5fdde707f649d3c552c855b599cdf951ecf1a58cd863b676d10251f65527c19f0fcdb886cd7ca6d35dd35c2f2c9bcfcd02924a355b4bceab54d0692336f70fd515d13e05a5c1f2adbf5903656da1c60ae4b4493bd720811f8f6799fca9ecd4034a5bc3d38f57497dd3d6cd91c15d2bd43febf748a14fb8242fef6a370ec9331a9516520fddd64159c6795dd13645bec29d69afcbaaafc773d19011c216d690c67ce5ed222d5b8609a570bf96502d7d43375cc76e057a6c129d9f6e7652b54ce286a2bbafa5c07e86a69dcad1e35468d609cd665328659c9af6939330e34da76c419bcd16d98f24301f54ced40f39e794fc3bd4edc96e05304544b241e701a828f44be5d37849ff5074bf6b434f7d0d72c7bd5b924c00de589ae4880a4cabc3dcdd2a0d24d39db9fda274290efa6901bcf8fc6d44a7ed14896419c44aae6cb5021ebe3af95af4fb7dc33ecabea5739c2f611ec67f46b577b91387b5d663f7d2a2523bff1542508b68244549c43479d972f3d076026bb722dfe1483148d8184463856c179f100e817b3c31d9229c77a1c344780856bd7a079a7a4b1caa383db17a30bdcdc31a9ada55eec04152b93611201fb73a801a634b18d06d20e1a70452593e5160fbe41a728fad12e562abedbaa1a884412c999a5eaabbd2957a5ac10b51c6bdc428643d7bc9007074271d95e2f7277f24ae1e781cd112afb0bc56fc16fa09ca6d4e83f1df582e6414ef355e8f628fa972ab4ad1c2eda71dc036b9d4e2a44f084a052401375d8acd8510bc5dd2a0750d67153b8138ed1974219e90286ef525df633753afdcc7b6ebd34ba5df989c90e3fb0281e318eee004b5164f9c7e1e1fa6bcbfad440232329474f3a0dc9805caefc271e764c9b6b16392c5bb312b6f6638e90409c25209c05b01a0055e44f0c0230b514c49f9dce9b7b15356019d0ecd25da4a683fa6deeb4b7c9a6c2a5aaccb8f891f6b47fd381b7941bef643b9e949178bdca0f127b0dc990bf53dec31469d5f90514185b76e8fbb0684e20114ae9ea086a9a78df34ca22d930d6151c267e6d347ba77638304f52c82e3dcd6d5cbf15265f753d06da75c05fceb7d01b3f8a732c16212d735377535d22ae887b4464053b043e20e5db71a009abe8e0154bd5ebc18229dbedd380b86656c4973c70784c0322bf5205c3b52bcb35535ae070200fd3f105ee78a922ccb0db9e4092ff45ef4479085ad7708081a71fbe999cee903042bd47b');

        ssvValidators[4].pubkey = bytes(hex'95dc732567172754d9a1764b0ce4aefba1c25d82983d964bafd26e8776c8b8197695b569b00321fa581eb70d528bca57');
        ssvValidators[4].sharesData = bytes(hex'a3650ce747d2607e97db9a5a6fae4c6cb47f2d841f7c211e957125dc7d278e99618cd2c0216c15514e561c7916785c9508f848ec1b51861539e1801d0733e0e8628cb9dad49938ec19d3cce4ee45f8c9493f63ae44b097e25d9d4390ebb90d6b8311cdcf9b0c095c629fab9362bb85e8c54442b06ba47270eb79798d60a9d10932fb6e5f7809060a825f556404aaeb0698e102fb84d0bd0d91c0a4c20b877377fb987e15f59c561ada9e5e7a22c56359d0579dba73b2d983171a23f5371397b689d73131a7abb3e740890690c5d8303f35be4a3e2f9676abd2110d73c441c9e3edccb33de024920f442dd5ccdada0790af587f570c07c3f36c84b5395285679733e4331f2adccda852ea06c973f8c6808636d92795fae76c0868bd6498b59b7f0cd7def637d60b5ef9a3c2786b01c21631d3a420a753682e0459b160de052caf480083e6b458f6fe153739b8f605103278f92d6fcc840f291bfef9cf2608e27ad1a7ccc96652ba0626ec938b6e5d4df4ef2ea019f4fc782f198e14e37b4080283d79adfd8bce5757d314adec7468d020b5565f99a7ec0031cf8f3986e1087d6fe3bfe87f126c06b5137626bd8411a66a2fda9b0c9776498707ff47d96fe378cfeecf094ec2e236e126e6b1760627c6bb06ecb39c8de314bd418ec533c1b432ab79f0e34176f4f3e148e1d48400e59a5d132c42bcd0d917604fa9a1d13f79441b06b1ca4e21a791683709498b9d71e14cef4a10d6934182262781c86543eaddcc8641ef169d96e1a8c48ffb895104b106ae035deb25ec842cc584f3e91c653b8b714f3f39396a3e7fe11687867fb193d68e2cc91e2d4b9768ab3bc4f1de45255f5cc62f5aa5f4d333b3ccf36dad3fa79d4608c934057ca37c386fc2647db450eefdb4b064ac4f7e61f9ef7236cf13e44bfdce0905ce274f356649d627433130109e1f301d90ebf69389ffe6db83fd5fae06c064815beebcf7779d5f774ae8cc3bb18b7c2f3b3d06f74164345b7a7bd12efacce8a7ec9a332c741cae4c024985ff722d457193ecd816546b6e5ed8581722d11e6df774d6a8772f2b2ba0412fb1bf0601e24ae6877a7c88e9f2aef22e240304fdebab67330870694f29c28d06a70e22683f38089210a23a5e6e74cb968647e7e4b8f560a42dd14b17d1975868493d367cae5114d5acb2f9bcf6934dd4db0c5b9113b6e9491d8d456c609366bb7c8d7dfb8e4b6e5a7107ca0e2d6382e57221c83e67e12b9dfe452a12ebf294884717f1e78b7001ba97dfc93ae97ba200a60adceaf072ad0609c1d637a45d58d96cd8757eeba5f12f2469c6a156f03b5ee0f6485d749cba7c7246a3e5097b3329374da538981d9188abdddb816c17190bdff1a29577f15076461b0189814e3bb117963dd990d47da8b0db6ce9d70b8308aa6c104889eeca832dfff12bfc5a84dad212a627d00bda93dc2bd2a5623678fce4c7045f52d816eed80344bd3969c190cff80ade824fc7748f166d789f28b39d9d5175cb58dd86ff12b3b0a15ce0a5a5f7feb46b36d938cbbe2019c0ca95009376da5d7780b197be27e4209b58da32e2a66bcafdfa94001cdb6645a3235491419b3c63caec502626a9538798b4043395de7b83d264326065a7a4edcb3425eae0a293639d23e8c85eb252903364de5c44acf7cc6e4d3cbd69231d0c3954ce94a3890ee897ce8cb388b58ea01ff2afecdecefc7507869fd00ad2c2f4ba541e28a3dcbe166c31cf17b1743b7b8f98d35230cc4aae70ecf0f54fbe4e8f3e81faebffdb61587f0f52e34adadd4534c12a68619fdf421457457c168e62e651db3d3d12350db68298036fb70b5c53f5bcb1b0ecbacb');

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
