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

contract Integration is Test {
    uint256 constant validatorCount = 3;

    IFeeDistributorFactory constant feeDistributorFactory = IFeeDistributorFactory(0x3FD4f7B62f6C17F8C1fB338c5b74B21873FF4385);
    IFeeDistributor constant referenceFeeDistributor = IFeeDistributor(0x6bb18EB3FbFF556d8b02E8eaDc5F51f21436Ec79);

    P2pSsvProxyFactory public p2pSsvProxyFactory;
    address public constant owner = 0x000000005504F0f5CF39b1eD609B892d23028E57; // 0x5124fcC2B3F99F571AD67D075643C743F38f1C34;
    // address public constant operator = 0x388C818CA8B9251b393131C08a736A67ccB19297;
    address public constant p2pSsvTokenHolder = 0x000000005504F0f5CF39b1eD609B892d23028E57; // 0xF977814e90dA44bFA03b6295A0616a897441aceC;
    IERC20 public constant ssvToken = IERC20(0x3a9f01091C446bdE031E39ea8354647AFef091E7); // IERC20(0x9D65fF81a3c488d585bBfb0Bfe3c7707c7917f54);
    address payable public constant clientAddress = payable(address(100500));

    function setUp() public {
        // vm.createSelectFork("mainnet", 18140648);
        vm.createSelectFork("goerli", 9882317);

        vm.startPrank(owner);
        p2pSsvProxyFactory = new P2pSsvProxyFactory(address(feeDistributorFactory), address(referenceFeeDistributor));

        P2pSsvProxy referenceP2pSsvProxy = new P2pSsvProxy(address(p2pSsvProxyFactory));
        p2pSsvProxyFactory.setReferenceP2pSsvProxy(address(referenceP2pSsvProxy));
        vm.stopPrank();
    }

    function getSnapshot(uint64 operatorId) private view returns(bytes32 snapshot) {
        uint256 p = uint256(keccak256("ssv.network.storage.main")) + 5;
        bytes32 slot1 = bytes32(uint256(keccak256(abi.encode(uint256(operatorId), p))) + 2);
        snapshot = vm.load(0xC3CD9A0aE89Fff83b71b58b6512D43F8a41f363D, slot1);
    }

    function test_snapshot() public view {
        uint64 operatorId = 2;
        uint32 snapshotBlock = uint32(uint256(getSnapshot(operatorId)));
        console.logUint(snapshotBlock);
    }

    function getSsvPayload() private view returns(SsvPayload memory) {
        uint256 operatorFeeExpanded = 956600000000;

        SsvOperator[] memory ssvOperators = new SsvOperator[](4);
        ssvOperators[0] = SsvOperator({
            owner: 0x9d4D2d2dd7F11953535691786690610512E26b6C,
            id: 1,
            snapshot: getSnapshot(1),
            fee: operatorFeeExpanded
        });
        ssvOperators[1].owner = 0x9d4D2d2dd7F11953535691786690610512E26b6C;
        ssvOperators[1].id = 2;
        ssvOperators[1].snapshot = (getSnapshot(2));
        ssvOperators[1].fee = operatorFeeExpanded;
        ssvOperators[2].owner = 0x9d4D2d2dd7F11953535691786690610512E26b6C;
        ssvOperators[2].id = 3;
        ssvOperators[2].snapshot = (getSnapshot(3));
        ssvOperators[2].fee = operatorFeeExpanded;
        ssvOperators[3].owner = 0x9d4D2d2dd7F11953535691786690610512E26b6C;
        ssvOperators[3].id = 4;
        ssvOperators[3].snapshot = (getSnapshot(4));
        ssvOperators[3].fee = operatorFeeExpanded;

        SsvValidator[] memory ssvValidators = new SsvValidator[](3);
        ssvValidators[0].pubkey = bytes(hex'85df5663b16e1f0212cd281fca814b8039b7573575bae286dd8406856e8179de4977542c1656e6e065b6c567e9f81a89');
        ssvValidators[0].sharesData = bytes(hex'b58312b249d15518a88fca12e094c406f5d7a5a418d7e2d8e5189261ddc8e06a29bcb77bfc3e972a90f3d127d14f8c1715d9079ccc5bf4d79c8ddfa6cae02015f8b49e839560fa4d65f21493c1aa9990b6acc2faae5f2941b83f1974f991dab08fbec5462850ad6d1fd5550ef607cd8b64a3d8658a22fad9c10db951aa049787d56ff73ea0b90dfe9b6a9e4a2020acef83a0c6ab1c5a339a09b41e6c86ea64d6bd982e7a42978c5e4b82ce244b474139668aac38b3f7d0e95712cd3f129082068e9bb19c60080d882dc04fa26564a854397908de9388a234f0bddaa430a3b1fa897a1f25125f9b927f701b111f45f385818b7350d82b31506b96cbb698223cb2618110d3ac54541a6f3891198ccb0fc7f97152c92db549b4cdf8fdb5d93236efcf883ee39cd3fd9388a765dab096c6697a95e26caabc5629a5886fb34d1c3df11f870bcef1fd47efcdc1798ef7ade1f483b542611db8487c7eaaf4f9fb32a4b75b05627f7dd21a6adfcb77575f5940947bae4831cd9aa0e0dfa3d40a26ebfccf149bfbfe73f0f2b04761a97227f680c16af002a981e79583a0c97493dacc095794f0b92e0e172881f9295d272aa9dfbc96d8d10a2761ba06411dc841d127e0fdf335dacd79361219dc0b90b5885a231d8e40c449ab8fcee3d55866f6b4ec6f6dfa4bae38e6f20f0003edc08d64b09e089053f520be3a07222ce8126497c6a907366034bc250605f378178492436a3b7887fa772cbc9084200e76df547beb5e9487ab7f74512bd76fe162acfb7437cf70cdd6cce1e24c2b1c77497265f22ba6cef34fa44a94e30a30a377aab0ee07dd6030c2ac56effa1f66df547bd912b9716abde0632ed045d896076c6df65103844bdd6d5a1435444631892f405a82231ed17e9f27a4bcbff56baae5dd3c2fe8f8405182aa97511a96d0fd5fa966dc23d69935d23322d4a7e1c281366f528c28c29ab39671cead5aa3ba3c413e388780eab7420d096922d76ae2020185529e6aa1e65701bd30e344acb67f47f567671d07d5a1939ddb1fa88a8f28ac33ab464b94cce3d541205cc51cafd5bb36e8a132f186b546819027834d5ca8ddf2609d26781d208605c5cce42026c35c0b08cd7c1c136e9e65e12f9aacf16e1169466bd76d90e04eedd3fa4095bb1d2dddb37b9b0a3a35f6d8347b8e73163ec83a681514926b7c612da98b30e30b1b9974ff3b77492809dfb22f63d58c47340a178ffa35dc25dbcb7f0c93c9e1b5b7aad4cb3c1863cabdb263490dc1f83ab0f18be5fa2c4fb5bb5728aac75e6540ff315712d2c2d79d12b9408f0b127d54a7db38c609f8176cc432de059e3ffbfd3d396888cfd94657a30b704f809721374f323c063ec9a97538716e43d02c620515c3893ceaa4b5a580c2081e8aadd54357e0f0724ed6cb9cfff35901fc4aa52569b4648ffce2226830d3294b1da3b1f6fb1134de35bfefab98bb0acc46a7e6bdd8ddec2366d60d5306e4040f91127f1bd3cf73f8943cf1b2b82bef17be5ea7cbd9ee54f292704b7a26beab043eaef357a9c41e58e860c2fca0276e1f1f5cc1ec0e8fe34c56988dd828ad3e5f7ec759deb8b254d01826f27f3d10bd95b4311fd11aec5a870969519813c0ec0a2a71d875c0dee4d1076a0d2bfb0f983fa32a430e164e3921d7b749bfc49ea4827e2863bea7dc3d9934c5a71177c67a3645f158192d76adc549ae45d7f09f83ec28a5767e093ea44afa9da1c3fe7642dfde4ef082409b96517b9f920cc2e248c58195024846112b9f4874b3283381ce5d42f133271cf775b624a7b90ee68bdea28cf3bb4fea20b26214c6cdc5cefae0809c43639febafecc241aea879');

        ssvValidators[1].pubkey = bytes(hex'a966f4ae7452cafcfea0c163fe7f8d17680b54d0697b798b3663485b3b60afb05357dd5f996eaebac9bd769705bff593');
        ssvValidators[1].sharesData = bytes(hex'973dbcf009d2a0a021a56d2c31c7e692e58e2767a516e4333273860ff9797d5c35bda6ca68e47d42ba9bbdb3d86139ed1881747998bd351c3a7826f44dcae9c84b37d9a6607f6706d5a55201610dd1cc780930ab5229cb4477896ba8ce661f06827c7ecd7abd8b1a1ffadb40f0162ea84c1e7719783ba01cc82422dccc106803ba44d0643d9ea6d4ddfb88697bb1470996aa51ff66e1ad14dbc4e292e73ecc44cd9adebd3fa2affd7c6b150e103e37cce229c6a408df7bd2d99f9abbe4500ace8586fe9091e41b39228be1d2fabb12de04654edfdbf760594e65d194c38a131ef3eb6872e6a507de02931e48aa95fbfd95fa3df012de74075702695e8580476d69a75e5231ca27fa6bb005707947ef57dcf5db223632cfe356ee1b7fac0d3ee05fc5e3eaf42f5709b2be11ece6f5a7ff4636c08832d1d9ec35293a14d1fad7f19ede1830d910d98e3f1513f46bd189e7d66cc914ce5123336b80edb3524728abd54692b98798d0e5b30a0c8f128e6341ab2eaeb76f2fbd62d4564b6cec7bdf85728e27c94876f9978fa5cd57c50def92a9089f0fb67999c3bd306de11c75a65758b4cb942e160bd741e243b94fe076cd411da75b3549da1ecf1397162b113d5cda22b7121dbc85eba3b393fec770c513f3009dc7cb418d6666b9fd1adb7dff86f44e5a6f375bcfe11c844f2251234f7a1322bf8ae1cea71efa31f99490e11e100912d2a48411f5e9d26a635fbe599cb2e71ef045b207bbc140988cebf707c11eaefcc559f03e3743518e46fe5a21cf0357352759ae5019cf57a91f96421ddefe56ad76fc61f1f1029a8b221bdc854e6d890f1470f66d8abc5e18cdb42b4e4a11ab47873667ff30b6974a2f4264753837e1635a201be4180b933182d1754d8b59d7cfd024b33e18a209275e6ccbbb869163bfa27ab5b9364fea98359071dd404bc8124c2798869b941df98be4bfeae0adaefd8f0bc98a3c666257d1d0a8a8bd394f336402369430d3423cca29b738c6a6b2bd62b65f483c5617934178a8d989201ea265f13c7cba60433cb2b6a8c0fc11c1c62b601fcfe3149a78afe8a00aa7c8e814b5114330875ac51a8a77c60533ae604431415eec85dc3d7c132b6517fed22aebe7131b7de7d38c39e22dc1ff5b6e018d03f5aad7c5c0e8fccba5b535aa94e9ade98ff41852e4409d2227c701aafb80d91ac2792b51a67c2ad9dd85336aa0e81e69c8ac30e2bf2f3a166d146171d8610490fbc81f08ac33b7ad1d6a280b4e593f2fd6463095e174bf6c8e6f8f513b25d0061d1b5a762b940cae9c29f37b809891b09327a720012783c564f44e34b874cb2c853fe7ac57f3daeb7a861516964777c69393077c97fbcd82d29e9563328731b9b9eea5efc0ce66576e45e970d68b3c1b7d8096fff94d6099675733b1639c1d393c654a02b8ba5e03be9b66029bad272d41679b0829e01351e4ccf3dcff1b371d442361ed76b8f85f4ab1301dee5dab85fd573614665f8142c03e2ee9a751b755dfea7d6c882cf9d130e706d9c3c9b17f0dd8743852ecbfa408c4aec4d8fee0a6c935623edfb137d4e16b0cccfb3bab70139cc7480a11adaaef16fd261ebd8625a2ad45e1811f549446495f4330c146bcd248f4ce905919a1522057a7854d986bc4b9a32f51c3c07813c029a8b21b902b5f1be9d1127f16466ae1a0afa8577c64695cf730238d7d386c4283bf1d89229069169cf48ee981253d6ac622f348744fa387c9a4d66f2f39fa2e6157ca9157a39afd103da79ada5bb175e387ce5fee6d0e3ae8a67d271de364a28f933c48c50921b4ab0faac298035c6ef21dcfdbec9699d63a634b3611e4541098d037');

        ssvValidators[2].pubkey = bytes(hex'adca0bc2cb890a89dfc1373259991326ba31d72aa800f9fab844119522a99acb80e32686e49ada0b94c68db0001e5736');
        ssvValidators[2].sharesData = bytes(hex'a59527381540b0acc072e8a3e2b9c287a1cb89b9852fffbb96435495f8bf3c6f32b3da7984fd4628d72cb494f6faa74704cbb7068520aad1342c187d822b1797b726d8532e658efe88d621b0712611751a19fa4b5fc493cb96be7a1546899631a2117f6302d46996735b76cc30f2f758df18ea1adc353312d3840055220a73ae819609f897fee324db678cdf40348530ad1d177320e40762f5a751895d1d2fbefdef4a973f433d161a956dfc927c4d35fe9ac425edb56015d71ebe86ad1b3d8cae28167b5f80199f44b2b739b8435ca782661d420eca0a2f2290f9ebcdb14ed0ab37f689091a446e6d3b7905b4924023a35397f66a67ef2a525438c4f0d0bae5c56731f74ccccca8b8682518851ddd18733a5b828e2708cd2095cb1679e716497a4d814f3ba600a3396731ca230df19c55bb3486bc9233a49cfad8e5701bedafc5b4cebcee7e0fda4078ecefbd5d7081e42ef35d9b624ccaf0bf78abd022c72c3b73304ee2329bcb74e65f6127ecd825f242b039a92be9f534d3be6f52b7258dccc4c98e8349694e8cd243f5bf5bb884fb8c2d7123e5363c999e4aef2718dd596037bd8cceda8242a712e1443600c0cfc556a065c2fafc76c7f06b2592a6fe4ca2c604ecafb788327a6f33255c0fa2c10c7296248de1a3ba23b8dd8c693ae269d56710e315caa53a96514f4de3d163888bf187da016dd25bf3459a4e84575dbfc3a4a16f7f0bf7793206605d8d5db95de70133f269c721775bdbfca50244d45f32c1825a6932ca927e08d0a75a6fdd42bbc8d45431b7463b4a715b48e0e7a3a72dc86c27709ad08b11d59a814c91fb70e87376867c54a07ede2d00a855d0fccf8da7d36feaa16fefef88a61a7c52f58af51807dc83cf99ad3caef55e8351e8f34e43e845bb414532629ea41d8e29d6390ef184fe64fb127d911006651aaf60b93095c31625fb2b421a86a677a916dbd223275e6db2bef8bdbbc672dae05c28118914692408607ac088fd698958e14305359685e7b8719c95a79b95d2b0d38c5440439a1da68f8aaa84f4a300adad89388086a2773f4530fc5ff13d9a299c654f1c7e45e67d259fd1aab71be28a5ef3f9a1218ec03d5cb995967bc4f38800fd9f8042a926111f707324209a3aca946bf58583df332448f986e269e96329c483db3e0037f763af9b264a36b3b3ebd4bdecd083d8f1a9868b130d0a960325ad773ab927859595804c32ffe994db18ca2951e75cb265de1043f254d7d8325664f3979b7f14736b3b126cf18dbc214faec49ed84965d6dd86fe04ca643da54dd262e1b980f2d93b6a21d979c4ad01774096afbecf1025e9e1967d98c12e5b14a6750153cafa5e0a1db95eaf8c09755060d1c4846bf2dbfb34daa1f6bd09af9a7e37ae066c6d13b2f5fe9f437b934e6f9f02fc1be30a130478c04d9910162e1d6d5dff8f222ac18a956957056d78c23ace4f3b669c8873b20f395282392bb5257f2d243bf68ae3dec0bf8f94e6fd0aa26bc5835eec8b42368786119a41e599332b7745e10a4d6157e14bfc364257d0cb1477c53034c84fd675d48570afed92e0fc78011fb53db2367bfd07e0c0b3580a2bc561a973db30806a0bd7c5034cb9efe3e210b41cc3371f7802c924cae448dc1d56d74f273babec66916484ab3c5f69ac84262f8be6e631e1f5aa9e34668f5afce26dfbdf5ba160b947e94c0d091c2a630eadd544dd65b3e92f229eda559c71d80898e2332dc0056b29d8fa03e20499cbe7ba23468e01da68beff2e85fb6cf0f47f080114a15b50260abda820d3df6f1f806aea3277e3902590c4a92bc6d026559dc93667f5664bbeb1cce03c0ad0ac456d78');

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
            tokenAmount:3 * 11 ether
        });
    }

    function getDepositData() private pure returns(DepositData memory) {
        bytes[] memory signatures = new bytes[](3);
        signatures[0] = bytes(hex'827eac8f4d5fa3ce4c309fd5d388a019a52bb2a60cb65484f9aeea612110008447f44760a7595b02d250946924606c601659ce4c92d6f49b90ef955b250d27b743372d5a1fdde7d27f2d273d0cfb0e05f8b4074994cc5e1475b04cd55c1151bd');
        signatures[1] = bytes(hex'986bd802004e2ff7dfcfce2e6f726dd29517823d4381786a176cf7406fa2aaff99c1993010a1e1e8b2533044859b9234033926262784f42e598baf3b1801082157843c81c11fdbd78c4e75c15efcf46ca9f4e72935183b55a28303ca61fa42ba');
        signatures[2] = bytes(hex'a4e9fd994b0bd88a730c98b2176263be604891ea35d54c18e8104cbbe44d35e9f4dd88ebf344672ac53ff7fb946e0aa31998100c8258c5666632504dc02ebcdc71e969164aadf033977fce3cd6d12623f1fe651daf11000ea29cc8e1da356549');

        bytes32[] memory depositDataRoots = new bytes32[](3);
        depositDataRoots[0] = bytes32(hex'5c106e0e12f4b11412cbf6610f7a0314166712405ce95eb0b9eeee324d23e9bb');
        depositDataRoots[1] = bytes32(hex'fbd27eef624027cb47d3a83a10f18752832e538f38f100b9050ef0216ce6a9e9');
        depositDataRoots[2] = bytes32(hex'1bfb75d79d628863886bd0374908d33e2aecb2410567b81a82f253ba5c5470db');

        address withdrawalCredentialsAddress = owner;

        return DepositData({
            signatures: signatures,
            depositDataRoots: depositDataRoots,
            withdrawalCredentialsAddress: withdrawalCredentialsAddress
        });
    }

    function test_depositEthAndRegisterValidators() public {
        console.log("test_depositEthAndRegisterValidators started");

        vm.startPrank(p2pSsvTokenHolder);
        ssvToken.transfer(address(p2pSsvProxyFactory), 50 ether);
        vm.stopPrank();

        bytes32 mevRelay = bytes32(hex'4242');

        FeeRecipient memory clientConfig = FeeRecipient({
            recipient: clientAddress,
            basisPoints: 0
        });
        FeeRecipient memory referrerConfig = FeeRecipient({
            recipient: payable(address(0)),
            basisPoints: 0
        });

        SsvPayload memory ssvPayload = getSsvPayload();
        address[] memory allowedSsvOperatorOwners = new address[](1);
        allowedSsvOperatorOwners[0] = ssvPayload.ssvOperators[0].owner;

        vm.startPrank(owner);
        p2pSsvProxyFactory.setAllowedSsvOperatorOwners(allowedSsvOperatorOwners);
        IChangeOperator(address(feeDistributorFactory)).changeOperator(address(p2pSsvProxyFactory));
        vm.stopPrank();

        vm.startPrank(allowedSsvOperatorOwners[0]);
        uint64[8] memory operatorIds = [uint64(1),2,3,4,0,0,0,0];
        p2pSsvProxyFactory.setSsvOperatorIds(operatorIds);
        vm.stopPrank();

        vm.deal(owner, 1000 ether);
        vm.startPrank(owner);

        p2pSsvProxyFactory.depositEthAndRegisterValidators{value: 96 ether}(
            getDepositData(),
            ssvPayload,
            mevRelay,
            clientConfig,
            referrerConfig
        );

        vm.stopPrank();

        console.log("test_depositEthAndRegisterValidators finsihed");
    }

    function test_registerValidators() public {
        console.log("test_registerValidators started");

        vm.startPrank(p2pSsvTokenHolder);
        ssvToken.transfer(address(p2pSsvProxyFactory), 50 ether);
        vm.stopPrank();

        bytes32 mevRelay = bytes32(hex'4242');

        FeeRecipient memory clientConfig = FeeRecipient({
            recipient: clientAddress,
            basisPoints: 0
        });
        FeeRecipient memory referrerConfig = FeeRecipient({
            recipient: payable(address(0)),
            basisPoints: 0
        });

        SsvPayload memory ssvPayload = getSsvPayload();
        address[] memory allowedSsvOperatorOwners = new address[](1);
        allowedSsvOperatorOwners[0] = ssvPayload.ssvOperators[0].owner;

        vm.startPrank(owner);
        p2pSsvProxyFactory.setAllowedSsvOperatorOwners(allowedSsvOperatorOwners);
        IChangeOperator(address(feeDistributorFactory)).changeOperator(address(p2pSsvProxyFactory));
        p2pSsvProxyFactory.setSsvPerEthExchangeRateDividedByWei(7539000000000000);
        vm.stopPrank();

        vm.startPrank(allowedSsvOperatorOwners[0]);
        uint64[8] memory operatorIds = [uint64(1),2,3,4,5,6,7,8];
        p2pSsvProxyFactory.setSsvOperatorIds(operatorIds);
        vm.stopPrank();

        vm.deal(owner, 1000 ether);
        vm.startPrank(owner);

        uint256 neededEth = p2pSsvProxyFactory.neededAmountOfEtherToCoverSsvFees(ssvPayload.tokenAmount);

        p2pSsvProxyFactory.registerValidators{value: neededEth}(
            ssvPayload,
            mevRelay,
            clientConfig,
            referrerConfig
        );

        vm.stopPrank();

        console.log("test_registerValidators finsihed");
    }
}
