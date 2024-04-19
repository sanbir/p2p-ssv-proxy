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
import "../src/mocks/IMockSsvNetwork.sol";
import "../src/mocks/IMockSsvNetworkViews.sol";

contract MainnetIntegration is Test {
    address public constant ssvOwner = 0xb35096b074fdb9bBac63E3AdaE0Bbde512B2E6b6;
    address public constant ssvNetworkAddress = 0xDD9BC35aE942eF0cFa76930954a156B3fF30a4E1;
    IMockSsvNetworkViews public constant ssvNetworkViews = IMockSsvNetworkViews(0xafE830B6Ee262ba11cce5F32fDCd760FFE6a66e4);

    address public constant owner = 0x588ede4403DF0082C5ab245b35F0f79EB2d8033a;
    address public constant operator = 0x11491A091A64E7e8E4837fe728e380BDd42b8834;
    address public constant nobody = address(42);

    IERC20 public constant ssvToken = IERC20(0x9D65fF81a3c488d585bBfb0Bfe3c7707c7917f54);
    P2pSsvProxyFactory public p2pSsvProxyFactory;
    address payable public constant client = payable(address(0x62a90760c7ce5CBaDbb64188ad075e9A52518D41));
    address public constant withdrawalCredentialsAddress = 0x5fAAF1eFa2395f917Bdc627d7A89c5154E7E7CBf;
    
    IFeeDistributorFactory public constant feeDistributorFactory = IFeeDistributorFactory(0x86a9f3e908b4658A1327952Eb1eC297a4212E1bb);
    address public constant referenceFeeDistributor = 0x7109DeEb07aa9Eed1e2613F88b2f3E1e6C05163f;
    address public referenceP2pSsvProxy;
    ISSVClusters.Cluster public clusterAfter1stRegistation;

    FeeRecipient public clientConfig;
    FeeRecipient public referrerConfig;
    address public proxyAddress;

    uint64[] public operatorIds;
    address[] allowedSsvOperatorOwners;

    uint112 public constant SsvPerEthExchangeRateDividedByWei = 7539000000000000;
    uint112 public constant MaxSsvTokenAmountPerValidator = 30 ether;

    event ValidatorAdded(address indexed owner, uint64[] operatorIds, bytes publicKey, bytes shares, ISSVClusters.Cluster cluster);

    event ValidatorRemoved(address indexed owner, uint64[] operatorIds, bytes publicKey, ISSVClusters.Cluster cluster);

    event ClusterLiquidated(address indexed owner, uint64[] operatorIds, ISSVClusters.Cluster cluster);

    event ClusterReactivated(address indexed owner, uint64[] operatorIds, ISSVClusters.Cluster cluster);

    event ClusterWithdrawn(address indexed owner, uint64[] operatorIds, uint256 value, ISSVClusters.Cluster cluster);

    event ClusterDeposited(address indexed owner, uint64[] operatorIds, uint256 value, ISSVClusters.Cluster cluster);

    event FeeRecipientAddressUpdated(address indexed owner, address recipientAddress);

    event ValidatorExited(address indexed owner, uint64[] operatorIds, bytes publicKey);

    function setUp() public {
        vm.createSelectFork("mainnet", 19660814);

        vm.startPrank(owner);

        p2pSsvProxyFactory = new P2pSsvProxyFactory(address(feeDistributorFactory), referenceFeeDistributor);
        referenceP2pSsvProxy = address(new P2pSsvProxy(address(p2pSsvProxyFactory)));
        p2pSsvProxyFactory.setReferenceP2pSsvProxy(referenceP2pSsvProxy);

        operatorIds = new uint64[](4);
        operatorIds[0] = 375;
        operatorIds[1] = 379;
        operatorIds[2] = 383;
        operatorIds[3] = 387;

        allowedSsvOperatorOwners = new address[](4);
        allowedSsvOperatorOwners[0] = address(0xfeC26f2bC35420b4fcA1203EcDf689a6e2310363);
        allowedSsvOperatorOwners[1] = address(0x95b3D923060b7E6444d7C3F0FCb01e6F37F4c418);
        allowedSsvOperatorOwners[2] = address(0x47659cc5fB8CDC58bD68fEB8C78A8e19549d39C5);
        allowedSsvOperatorOwners[3] = address(0x9a792B1588882780Bed412796337E0909e51fAB7);

        p2pSsvProxyFactory.setAllowedSsvOperatorOwners(allowedSsvOperatorOwners);

        IChangeOperator(address(feeDistributorFactory)).changeOperator(address(p2pSsvProxyFactory));

        p2pSsvProxyFactory.setSsvOperatorIds([operatorIds[0],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], allowedSsvOperatorOwners[0]);
        p2pSsvProxyFactory.setSsvOperatorIds([operatorIds[1],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], allowedSsvOperatorOwners[1]);
        p2pSsvProxyFactory.setSsvOperatorIds([operatorIds[2],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], allowedSsvOperatorOwners[2]);
        p2pSsvProxyFactory.setSsvOperatorIds([operatorIds[3],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], allowedSsvOperatorOwners[3]);

        p2pSsvProxyFactory.setSsvPerEthExchangeRateDividedByWei(SsvPerEthExchangeRateDividedByWei);
        p2pSsvProxyFactory.setMaxSsvTokenAmountPerValidator(MaxSsvTokenAmountPerValidator);

        vm.stopPrank();

        deal(address(ssvToken), address(p2pSsvProxyFactory), 50000 ether);

        clientConfig = FeeRecipient({
            recipient: client,
            basisPoints: 9500
        });
        referrerConfig = FeeRecipient({
            recipient: payable(address(0)),
            basisPoints: 0
        });

        proxyAddress = predictProxyAddress();

        clusterAfter1stRegistation = ISSVClusters.Cluster({
            validatorCount: 5,
            networkFeeIndex: 65412084534,
            index: 4935309852,
            active: true,
            balance: 53460049500000000000
        });
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

    function setSsvOperator(SsvOperator[] memory ssvOperators, uint256 index) private view {
        ssvOperators[index].owner = allowedSsvOperatorOwners[index];
        ssvOperators[index].id = operatorIds[index];
        ssvOperators[index].snapshot = getSnapshot(operatorIds[index]);
        ssvOperators[index].fee = getOperatorFee(operatorIds[index]);
    }

    function getUpdatedSsvOperators() private view returns(SsvOperator[] memory ssvOperators) {
        ssvOperators = new SsvOperator[](4);
        setSsvOperator(ssvOperators, 0);
        setSsvOperator(ssvOperators, 1);
        setSsvOperator(ssvOperators, 2);
        setSsvOperator(ssvOperators, 3);
    }

    function getSsvValidators1() private pure returns(SsvValidator[] memory ssvValidators) {
        ssvValidators = new SsvValidator[](5);
        ssvValidators[0].pubkey = bytes(hex'acd2d075d65c8720edb01832d6d6317e8cc5d57579c72f2fa9589dceeee79474f683003c4652d43e735401d70be01426');
        ssvValidators[0].sharesData = bytes(hex'8e1bb93360c2d43c13ccf60bb43fdc9a47353fcb569bd9fab6507a0314362c3d5074fe1855823f6768fa91c25e886c3d0ad8a395a71ec4fede1ce70518a9f977e9b839c0aac13cf4e09bb74c5d4680d548ca9c7907f7c7d3cd52ea797ed9324ba99669cbea18463b1813d97d51e97635b3384c7dea718e18ccc1dbbe726a540eb9bd95cc09efb48d9d29d1125af0649bad1b7dd6e2dfbca929e68760b3637f25ffc64c31d48042a47c65c9362c790f53532d66ec97b5b09d3948df3fe9960190af2b823309f41dd6264f1c668e2435d16878d5fd19f145847d5f04a16257209a7f4077843cba3291dcd3d2cbbc61f06ead42d3e20c6507d19452c673e4be651343db4b161105d1f3b3d0de441a85e807529fc8e240bc8e3b229309e630617aa218ae1bb49a5ff15405ee8654498e3b7a9b0b8c4d7f8452060621c6ac5d3c5492a2a9090cce2ea37c45992e93b54982943b8c43467cc8c1faf788f7711ee4f30f8941f691f778ff4f6a7bacf0918fa7915fdd8d149021018d765a476b29b50a0333e11ef6617adb74cb6bac3658c5e2c449adce30be16dfb5cb89b3d65581770bf2b18b14d9284450a9be72f831c84e1f2a911635f76e4953e0c8239e80530452c9638a4a8d1604b62067ffe0ab4a316f8ab8278ca1dd845dfbf125a3b9859b68c945ce4b46d2ea779bb12c8ce756b2314ca50ff668e71ba18be4bc30ab10801a9d88faaf11547df75bca8137af11cd6a29868b5f8c6fd89bcd668c3e087107ce748f21fbf3f4cef46d932425d2c8c5dcba35f67d75b1b104387b3e340115a77fcb56bee63a130dc27145c2fae321e14aceaf816e47645461d2d1a6116f7d9ae28b0a9f1e91e3f90ffd4f1082c36431c39da3982604e7b58cb6926b9ff9ca6708a82b66b551f432f9ffe3418b761ab30a0e633f21a80738bd7e97055f08ae8f4690123d94e77d0c1691a54ff2d1fdabcb991cfa69573c24437f8bc7894be940a2fe8ac3aee5b88db8e2c0ec8c09d5fadd32884b62d86ca4bb6663a3a6f332c72cef9f06a96bd2aa912faf30fa2d3a6939e7d7b0db9b969b099c65b35b685c33863952db5e86e3998458bbde8885634caa58f0dee6eb53969639f892852507975ab3b96a735ef3189b5207f195d2a6ba525a13c54ba54951d24c69474d131765dcc5063126ad7a2d243b48f6bda2a8321ffb54259e9adadfd4743d0183982350472b84f5fda7dc1e02a389fac114152ba53d4f74c9f1232e7aa1fed1722da08e7253872c7dad5e9d43c1667d50939b925e6e052a87bd0a2f94571cf7de97c4cdc8bc3a6a25357067799c6ae8245446013d4a753410ef85b1d249c2a8d1d6f6604a5b2a4d791fa5d2b42239e7bc169ebd69d127bef0d2995431310f78a89a507c811e5a87c52ceab2d14c42610a230821d82d6a824ea6f9394ea32b511fc8ed959d28769db1cb7f6fec78642a5ed71aab2341d8ce124c2b494d1aa4013c05420d641a6efb234c675cd3c46f1c3937deee6bc4e584b10bbe0bde1b11bc6e356ced86a256ecfd0492be1c2c822e54d7cba99e956c78eb6ee0aeee30a4db57390c2beae338e9c0a9b1d8c66644b1cec310965194f0746a5e6455b12613f9be6cc5bb3b8d03bbc731b951b1cdc4b1a996bd0cdb449c75b991555df9ebdecb626bc730e750004a23ce817c41233d76c36acbd295cc2ecf5343e00b3d68183503a85fa8e4156b18ef3bfb90f90749e0fcfb7f97eb75e208db93cf3717c0b94cb18e3ad6c51c9aeb57790a21de7efda8aa1089e7a0233ac70b9ee736874f801484bd05d2f9276fe8b33f7329b560d6decd18e28732b8ccbb010f55bcf2eb43274f078e87a4');

        ssvValidators[1].pubkey = bytes(hex'aa21fa31712e3ff2022054130c5f5af88b6b3291539dce5d85ec5d32e04feea7920eee439a0e8bbd20d4b949af22c6a0');
        ssvValidators[1].sharesData = bytes(hex'ac3fc0e2ba59131a257c308ba4f55e902bffc6a56d43dd92d5c946af41ac8269df79a26bd4503f6bdca87cda06525c84133b3ccf1813bebb18390c7a2ea5b07de30a91ad688bdaed4f25f5b8ae3ea32fc31f9495b7e0e12680c2b5f826064da28f5c7952e80b744ea9d6a25e17cef0d644ae1518393ec955f3109afc2efe9ea363274d3d6e29b97a2dc61aeacfb483d89529596d21ca3e786a903a9805f5545d49b467e7cf3d5c1e5bb57fcd10b60232ba21fcecac0cdbeb74b77bf2f46ffae899bd4708874d2db3d306e9f86d7fde574be7af978519a77aef239df126fbe1fd46ba23ec439ff37a7afba62bcfbb4c649019611f7c224b2578538024929a83d082eccd548219586034ebea0fd33060b7443dbfa1d600754a372d1f383a6f6bee6abce6ae0487dfe9056431468cbf7ccb8614dc573d6e8f6db4b4c7669fac8b6eb24faf68cdd6f6e4df8cf135cd5a357d1136f9a3cbf851df4c978cce0b83a6e7230cb41b628e0042fd18d08389ab901aafa9a79768a987ca00819bbe3ca558dc21877c9571737bc383abc6499ebc4091910f27b08dad338e47f433b836e7e344ce6d4790cdf535374c119276c71f67beb6103993dbef8333dae86c3da5aae8b672ee36569efb821e54f465035deaf653dbd210a8258ca3b9a3f783c490d0c38346eee1619c823ba897a6a26fb2ab3fabda994dcedd849cb3d9b3e560b9c090b5cfbc003b1e2fb5203b11bcbb3fdc5fef9d6d1a15351d03ccf3d4c2d70955a8560747fdfa751df6abdb95ab261a3eb128eb330235f90dcd815b0e680c97f1f90224aea4eef9e559529ed88237c60203b633a8552703665ffdf739e1668397bd3b452277c4d9243eee447c3f97a88866e59d5f6f24b4bd4ed49bf3a09701b16893fbd0f0b06787b1d01a6312d2dff7886ed4a3d2e6c8550b96c058b422d9be4ea1b3f87adba6868e59872e478b737c84d1eddfbbf08d1f12d81c60601b5b90c825c8bb9132ffae8ebebfe038cddc2d4a86969817904e9c4c14ad8b518f89248e1da9e012fcd3cc862f37f973b268dbd10658dcd296601bf4b0c738ba8272907f57630d2a2b85606fcdc91dd8afa8818a271cb90d82fdd6ed16b24997e20a9ec11a4ee65c6c711a885230505b60ca0fba7c64cc04b28e3c7bb3ea3189d323885834ac72ffdda01a40642da10b0786d541c84805e49e4aef57e8a0a07d68c498a1f6433c481daf29a96907c1b66f4ed982c014bf02462cfca22bac2348fade2dd8864ed548e8997c003dd1abe0c0e8323de79678d2fdb7268e13cf3fa21bc85822db2949d041277015aa0be56255496d765b427390cacdd361b82a3772951241bbc890c1a33c1d1dfe387e1c453bbf0e117981f634df0de1332a18e4ff15ff5fc90bcec9c59188ab06cbaa4881b37e30e13185e5a505af59f5a25a69b978e8f0f2ee7c08b375d55a405baade77539cb066551edc87e991bfc9d8bddd118f4a4c5a2905f0aa2a027ec9606cf7e4247be144659f1dc60f517b7116951a932d1378d07b6d2f2095e87bdf2782d61d940f7812d0f6595310bfdb8b74134c9be98ffd390b1617f93cf0034e07ed65dceeb78d26eda31dde4caa635a7ee055753733df9bd9b3669dcfdd9cf639e3afcd2ecc4d1dce26a81be5f112b1ef1d569aa097a7633419455812eb132e5b1dd85a4e933ee2eb32658ba1ccd540fb8166190e7fee96719a058f0026e1c3ea7b9be97cec2799c39c947308578534462cf608ddefeac62d694fb43d6fa8e67dd2e0ffce065d21e5a7066bdc6f0b678e3b3aa5389be04ed5033a0cb821499a99a05770f8c56a6228e21a5cee6e0f58703834c24646caecf2');

        ssvValidators[2].pubkey = bytes(hex'9796d3d0d5f94527381b0523b919d4cb2a41d43f7ac01e6aec121324d48d66292a1cfa533ea5263dd3fbd2433d847653');
        ssvValidators[2].sharesData = bytes(hex'ac292e4ae90b7f2e95deb759891a39989d5d96f48072f060aefbff31726c12b924f5e570943b776e8b07887f9f83f4d4129929c0f9a8b51ec077ffd026cf0c7dcf22f44a995044a066945fbd977da98d5afbe0954d11f26383b4cf248060ca6f80d3a4b7e0f364f266addd5135fd78027b280fbe27035dcc37ba89ec741851342577b7967d271c793a452d5c6fb2cc90830370c97f7706bb1b828220a7f7ae8e81344a015c6bbd0e04d031e151508dfb12e6a50665d6476e9772337587a457e8a91126a2694ec3145210a14d65018425b6c967ea8d920e22cf3ae9f92aab30c86e00d4205a4d567fd4dc6894c74c6765801e96c7b8c7bdf072dcc4666dcd416c26c39cfe31f3d229613ae0258d77595488051359e4cd379c38877d49042fb857545dd31fb97e888bce82e56549d6cd37bd34ab4aceda29b8d2ab85d68e1bbe9d2fe6cf87b07686a4846b0f324f618b17c99148809f16de74c1a47e7b3bee2224dab3a765295ac4469e2bed2803baa2e7459dccc03d18bbb2c1deec676c6aaf71e4ab2d8fe82f51b888e489984112b7248843baebe92aab7a10b39e5fde1c656a9fbeed306f02bc732dc4affa98ae3999138b7accbfdf92d75f15f8ea8f37a3a92538b3ea7c250690dd0f5acc87dfaa375601b05e980ed617dbc2e108a8cf71dc394a520b814028029b6824b1e6c7e9f5769651a839201e3916eaece20eef3eed10b5485de738b282e23ecc89b55b565fc5730b3fc562d5bece1ddd2908fa025d19e86b87faf69a0ad1c4b9c317f8239aa0dcbcc1c85da650ae62b203a4a39579d522950f3b7b9917ab55da1ec127d11a348beefdc9dc1c7590ccaebbf7a99ce736a50b093eb6c9a722da75007deda5f12de8159c6c75ecc6650e3cc07d67a58acc5a433ee087c1cff2d14b682aeb0425e844a8e3be4cb5e0eb5d933949bcdeca12be90f08fe23aa7a19250548b3ad1e0b75b3edb2733ba611dcbec376f642f10b71fbffd11d1970da30f540598d5c6fdf1c0909da1aad31d0db1b8549745a3505b94178e264cce5ddc8db774b259c8fd91f7b178e6fac7872792cc01501f4149984fa41ab409ef485efc5c9215b1d3a008edcf8c18b96cc038a254f7b47ea73695640546d14ad7508efc19385d798a2fb825f893b53651fa51457fabf313434e80d0be3ed5065d3a3c9ac925c085292166fc04a979e1bd516317dc5512f7b54747e84395038799ce17f9430fc79a1b694c623006a8c8395360254aa539860217388538bf9cd9da7e265c2dfd2933638e95dd197d2d7a32bd7ad87edf7620bbdb9980d4e28b40a1c892915cce948593d8037cedbaafd48abfac89ca6de970a769ff620e44000fff703d9b773acbaf28dc8fb6b2da1c0e45b950ebbe2d7ad98a229ff6c670d1fede8b9dc496ee5740e25d9173cb582a867154e0e3036da546546d0502e8ba84fd33225c4944c4e17c54cbceff83c933326760fbb8331db86126e838f3784e2f431b8c7e580702429237b226b783616b4e2a9285ca0b37659b5332a4ffefd714171c7f280affed21a38a52d79e82badc5da52a46ed143d13205c2866c69ae468d53eec9d8e463e69d23223e9c3a45348ba269112941fd1f852ec80df1d988ee568f742d2fce53385bd2b2390bb33289246e6f6850e31fd0df54d3d1f8a1c14330eb8d33e21625f06cdceeac8b642f42a2a55a3f5d459c4ce30c472626b1719b4d88b7c3806b89a47f71fd27db96fc08dd990c63d699602f9720bd79e2eb6d785e38e6897f95039731d1d4e4d00568b26d65c2be9f9c38dd36dbf0c55727f6c05f26f66f3511b80f6f7c90229d6b934e450ce6074326adacd25e798');

        ssvValidators[3].pubkey = bytes(hex'a1674f0531800c1c683c9547dcc7de74f6f5bd0d54ae863eaeb4f275da40cdff9329b5b8d7a183f37807f839f097a8cb');
        ssvValidators[3].sharesData = bytes(hex'b965bb486dc4d462295f4e2b1d9a8bdb090a58b33e797d8b7be7ec432f7ebc6f2de8da3eaebc2f33f33ceaa793a3344819d85ece4d22fcaa87746cc7e45eec1907f1be1c3b7eb883a9dcacc7b800a38478644228404227c5d9b85fe9f4915adfaddb6c977f2cba2d77dad8298bbb6c4c3bcca412aa89cbe49539e5d1ba7100b5760266337ad6deaa0fcca2080f5b85a190b9e3d319b26d0ca05cbea74cc0e953281565778494c8cf42b7ea98849bd3d297597689eee46d4a315bba8f51ddb7e1b43fd508900e259de46bb50b914a1bcd9bc0438f70c27e1e32ab8607fb8b7470ab263b1725659de3a4c1e013e09a44b4aa55d12b500d55e8c0f343a798979c355e034153451e20df7e5392d4344426dba10f5b0dcc651e86607c022a63e52e5ed78f2def35955513911c6af079e6cf0d5439f32c2ca42408f8b20e7fe327c1b1ff9692394ce243dc45c33c3bfd890bcbbf9ecf797d9eaef57f5490f7002db1ac5827fca5bcc80932c1c6dcfe608de36ae21a4a99bd83d8082e04dc95d57ca8537d4caf95810d7268ec436c8a5572eb51464c64e1b12bf0fd5ac429d049cdc84b9499dd85038fc63794e49ea8f5412bfb5f1b587624803eb53831b908b8a5496035b900b9aa9d55c395407725002fadbb0f3557367a8ff67c9423a04cd63ab9d07f7847568be977c700c6c5f7ab5e607229e7b08c9f65661d8c3c83427d624c172b7c887768b9a903d5f197774c72128030022375aaac60a33ea598c448d8fe2841156743783bbd4f5df62a765c4dd5389985395926564d926f3b9b68b7a91a2a04238d85a1ee4518e2c7760fc35f89c960837a4f5c22211f36f78b98a7a37f17a24393e1c39cc6e3a391b250238176304950982cd692cca4712ddf191658c632f534c08db176fcac1b2373568b7b90308a541bbde9f3924d4aeac382c86246bd343cbf6fa8c90e29ec75e11f871746243936ba10f5a3d907ddebb36afc679972e4e092f203731978e5845c82b367d14991c2098e316b56ce9706be1c3d2bae9e5e26593f5ab20a4afefd79e37efef2e9cf1b02ff746f0e19ff81698b28ae529c6729cdb0ad7af41e2c95ef4594315a262a2448db6360b2d2ef758fa866d7b1059146549b4c8f546c3c42be7bc4359823fba5cdb31dc84d1a7835b5a8514ba16dbbbf24aa09e3e60107b91c1120f7ab00d471dd0accf09d53331c8cf4e734424ab688ff8a02c775c3e37f81ef535e6580aa08291aef8086b676aded406398bdf97ec45f367cd42fdb1a3b3afc3ac6cc8e3f8dd73e0e4569a68336d41f64413443d79c057bca5c944b1a6a06f32684bea4a199a628fdbedb2d48e0e362cb1d00b66842faf0745d914f2b5be366388c029830a08b96bf4cc4625a9eae6506956694eeddf77b926c071744370ea75ab25a263903df2119ea001244e0bebe0b71784865c9defbd2f478066ddd86c5a8ac4f55ee700e7e9e0e5ecb7a55f2dae0e7c4a78254a5007d6bb659fb666bb561387e8c4597796df8e2f883158d95296e0ceb965c1560ed3fbc1edb4b83bfbc1e4b656ef533ab1ffa48f5db4cde5d087a7ae308b6873b4791ebf4f2c3e912f338054a865bcd1f0c650f11bcbfda04ace2d83708a73e077e8dd1317f7659b0478c3b83e9663d8a5592870f58adda33e9f1ae8673d831f9e2cd7c29b2bb2fd74b620bf9fc86ba2070404770304cf8bda33e601c5d6b8afbd585cd58fe75b56bf7a5503b6720ff2b0a5791812e0d263cf25654f6ebbf13f834b3ba40dc4fb06374f5e7853326864c63f53049221fc479035786e3f86b73a4b4f573fddb1075c599e48b102f9784919c100b12113801ec1acadf6575');

        ssvValidators[4].pubkey = bytes(hex'abfad625a586b68f5588f06d56060829e2b564608eb55329be3cf2eaf6040b4047a1814584bb6a285522987679f3a1db');
        ssvValidators[4].sharesData = bytes(hex'96d05defa1ff4bd8e78110a1812d0bb0ac31897b28c272c7bc2b9c1a9378f2f1e1af87812420ff679d7d8c0909f8544d0ec34f4927f0791931ed29df2c6c2dbbbcacc8a8d5a723be93ed5b17a64bf5c72067db3a57a2c47a4b5a1127b53d31238822cc4a19a045cc10e92bc1b1d20abeb4720fc71d067bc9ceae91719ec877d28975943bf632500096bf78908e7a515b871867f672b064a57ae168bca867478817ce086f15ac2c7357a4a083f2d09028cdeda16eb00100ed3928fa52846f63a48c8fddb5ccb03cee4ef50a452dfef11a698f7b1ed94e61cd2fc7fad3d10bc33be1abba6e4a39c93d95106b829b08ffbab35c2b8fab6030495fd3d201911b8485eed657187d0f6b69d902b61b57feeffc664f56e7e68f3eca2142dfbcbd0b6d13af7d0786bfcce9a081f69cfb6a4d5613d8a40cc26c9220d9e9cddb2e8054a7e6e31b9524051082af5d6f5d764156bc5d0f1e03d177ef48535d854523e936526f9b3cedf85ea3711314ab85cc631c3a30c170a5b259f673b9b818989b150a9ca31fbde22f24b9a2a9cc15509dd2f42e9da4f5db61da90476b5ef56ce3c12e2ca588d7cde03bf63c23fb86032ad55c7457259f3b796b87226610452e4fbdb365f33acfce596ba2f374c7dfb59347579da212937152ae2621fbb0c713e6714d5095f813de48bb1b3fbba2d1ecdeab575445fb44a300c87480f13409beb82b76de8ea622d19d2b0f431efe04433749f12b047b9f4e6f342021fd9130e4bd529c386160db54b3ce49fdd8a57745fe0d7b736ad6f0b4a03ca697e64539cf1140e8418c49799a61b69e4f048ab8cbbe0514433c7640c9c621003bb808912b73271e7d61365d6231b3a162877c8e68f9a4d298c4a8f2749003f3b3dbd44a8f923d3a82dfde0691221f775e50fd64e3cec4b5dd8373c7a637f15d07a5f72d01e0e51031dfd11704b92a4ae5cfbd734c2d881644bb113e5feb00770cc5f1a3a2ba5be0ee81b310bca253583a6eb03a9477ecb2d6db097448054a6b1d3e4a4d9e36ec40883cf6a241719048f9396aa9a6a479e0eb28d1d90d6a8be7124377bc793e6fcea04025ad6329f025dcab951cf80482ad578774cbb8d0c4ed00179fc25ac3f8393a7a10ee6f2425e8d5555324f875cab338934c5a10201335106e7b4b808e97c80e21ddfc3feaa5f208099641ff3833a6757799e23d82c6cd4a018edb5bed5c780f9d2575befa762ee7839d5a97c8867ddf60957299cfb8501c333f2e12ec3465c7bb60b165b2238126bdb5c5fc583a79151cb689d3849acc2ba4aafd866aa370a07a64241703c2eb5fbc44395d6df2fcc7e51f38445569393f120c96fb588bd2982956350bad103b5b7d988ad0a2f3749927ab0958e6d38328ba46da71a2b819a5549bdfa4e5cd1d759ff18cc40db064f8def5354fa52662e6c68ecbcd469d5e949779f9b644238b6787193d6188585a492e54a93a564d122466a98a38d427ebd25d8d83c2da5938ef3d0bf23cc88cb2eb259c110436c3c5c429a152b87ffdde1667b365fd78ab794f9f1df50458f4c338fc0c94d157a2e16464fd298ebdef5f3233778bb8cb05e45b9b86af330f1fc4dc082c17ca6f23e5475834b89c08a670d4057b35f3e61d2cab03cb236075a05fe7e218da0c93a360bb4989fe796052b42225ade38b639605f7878b6bd6ae54ad099e163bc58e6526997345f20c46b7a31010ee34737207eafa3b23f077e933b7eb59f4014f5fceb756deea0c510b13bd10e9e0f911b06f4fed668336492179764d1d185edcbc18dc3d0f22d4259907339aed2ac49bf24e15520fda44fd6c0c9bdfc15268636ac3203dc77bf0ce6d6ccfdd0a');
    }

    function getSsvValidators2() private pure returns(SsvValidator[] memory ssvValidators) {
        ssvValidators = new SsvValidator[](2);
        ssvValidators[0].pubkey = bytes(hex'afe021bfe48bca8c8057121eae716a415b08c7da0602f91bb44272a51035b14f12fc4008a8baf752a2b6ee116f4d1840');
        ssvValidators[0].sharesData = bytes(hex'a4cccaffd02678a5ac3a827b1a784c0f8ab7cc262c5c12e7449141287a8ec2e8b8102be6720174f2b6eabceacb4dba4d114725c1e19dbcd5a9bf87c3d0b47e96ea61caa3bba84396789dca94b2bcbe4bd2e507310041d911ff2a5e2e06406c799789450fbec2cfaec66cc7c8f7fb4c3d3a677270e8c27da4e0b3e7412dca37e4b7401aab50d129649ba82230a950b39394739857dea3e74aa20e08e83a7bf3ca9b8102880baad48603074cf6c4d6ae80ea31280a4fe83070fa7c96ef0b81fc5da92ef423115665621d931af2fd20f409fca0a597893eb7a329af6ce41291850ff2f0894a78982887e38c7b555d80cd53b8c0e535d94adb00c5147018057ee7899a5f4724e5d145bc784fc823d967bc6b9e76ea9d2a1044de7ac41a6fc866b5e8934367d10d4745ae4ff7cf2d06f01ff72ab946480237a6a0b0be06292d3bd8370c1c416c54525403f842999f85339d3e47f044b56e723b6f0f3f12893a470e8a7bb0d78f92d25ce3d294adc23a742dde22a4ec154f1f51cc5c411a32a470aff1e93a19d51fb139a646a343c8f653baebf1aadf72a2e8c180d1751afa8e2eee26fc94964c88a4426d7292472891420c2ebc84701d7353c1a0525e1facafc410f252d54c6739c609007d69c32980aa8a5ffde2a48d0261305c14b63f7587d524927f6447cfcb82f232393a1a401cbb789ac97de1cee9ce20921a189b0ac67d187d3a4092a8d60535925a1b29bda55c4f6c2412206a866b5fbc53f274471ce84b293bf106f1b35ba32613fad45495b609c9b9f0257b094b2becf47a95edc1a677b64ecfe21b991253aaeee0183ee41467d54a17b324f92cc3abca182ff4758ecd4b24c804329dff101afcb9ed70561dd8c838df05fb3b9482249a32d4e1ad10e9a86ca86cda0c2796898c0694c8af4559162736e5d028bd9d8873f01b9fe7456359fc459ce6cf900ec09a3bbd72d5d65fceeb259b2f401783ec9f705ab5c27b4fe5ad7070e77fe2984aa7376ba85648eb284eddfe8e12622429c47b4c2c80ac98948e1b91da7146769bfc1566ba28ff484fa8835f85c616fec48af92aa943fb95acfc92c5988787c91158ba1ef87df5f6a399a3a06adf71ec10b3593498038f9c8c2959b2bc87308fddd4bb3cc7fa1094733109a259e49c1f2a7f21911b8f1b6c5d5e78c2bca0922741ddfd6c530fb3bd8b6d916e1f579739e2958e81c64669e2700855ade426197120a763d7a90ac94fd2e62b3737bc180770d2d8294c751c4c2430d6c1cf9fe71ff856bbb08a70c74250a1653d749e0d2a195ac6b25a492433f2af9a6423f8cc346fa7c25462ff0ed47f52e0cd4ac76dc65f09c8f3ae187779487f36f2d374b06f99cb0a7af5ffeca6980e3a029a10d9dbf4d761ee3b08b794735a10412647b1839c801cf977fe54ea760e928c04df6c861fa5e0a29cb4fb427968447365c17e12f8bfd36fd20a2ba28f5032303a785c7bb859428838734b8fc076afae1e82435b47cb433c03c8938640f9c37e8c568ea70d479811740663f6507a6df938deb8d20647fd209ac54ff36c04c86bdace6ea37e97b1399427bd477ad8f3e4e5a1291a58db98a495bd5716f8ea529868300c9dd15945ad60b012e508d83f2a69a6676a7d19c2e75e7300b9886ae701451173e4a0dcb0b16abec6181022b900ff75f82250b3b8147db1219c132f0d927c7ca7e9575f46297b99f1ae5fd93221798ba066e4e80e93e002d076c02dea9cfbf1c36798763791e6f6752b7e91fffa8d18832e1082492668cd94c253f9cc31d57e527005f13d9c03e3da5d7f8fb50c68db5b1567a24e999fa1f77663abed35474844a8b0dd1f438125ec1f32');

        ssvValidators[1].pubkey = bytes(hex'926f87a60622b73640c13e95cd95614b2d1f1cc3e1752b259458adda3fda8d7ae3a03ffc252e45167494a38220c5aec2');
        ssvValidators[1].sharesData = bytes(hex'848be0b11ccd19e3c98019cfc1cee755ccbfb103a7589b6aeb991bca1389e07400e5f2b3cbe9bf281cf54174db29503009270f557f7feac4f12b8d4f5970dcfca40ab94a09f176fd11e40903e442c30e7ccd67a523aa9a6e77a665a4ac4950c3a68952c1e35402794c62f1e253f65d4815c4922548f3c6d0ad54ea76a4e698899fd160911ca70a41b418fcc141b9907bacb39ad672ab9e34d66b32f9edb0580e5847fb3ea99750f81b67fb226ac9560e93fec527210986536b9556a55cd6102fb212a840896d13c7e7973cec35f7fe2b29dd41920b646fb3811f042ad58bb514991a4dd5e43e214752783665692c0921922c7855a543ffa782a73025fd2821b653da29e1b25f44e2dd00a6366ff7d3b3c77cd51398b7d2153db5634162192aaec83bd06088f9e182436e59403381585cb67cd98aaac070b0e6ed0aaba4ed78107f27eae7d91b0b7f8f9d27e44da25a3a0f75de01bb8a8946097e739bf84701ce70d1c86d7d27883e35d6b67632e350616a07e1724684560ff9447aa735746c61d9f00ed583dcdc61581b470d94305f5e26360348932b48fdf192ebd02d5dcfef1259c4a4b2c312b034023cd7dd8ac54d164b21d55fcf5ce5ea62e558d14a5e2ba17330d21fe005e4eb2cb9342568c758b3f8644a33f2dd2bd592aa2f71d37987a1eded540cee5edb836f6c30cbdd69fb04415f867a7e62fa9e620878f3b0cbd7425bd601b08eab9af31d8809df62d3ad3b7f1b9e697fe0e29844e418ad9a8c1c991fb69e335797a7a71fb534ef88f3142c66027f7f7dc154423a2378f0eccb33d2780f865ff49bd171038254a3777822b56024cbce907995a2d50747b5452fed157fec3e19a59ee3ef55c155aa7fc6728c0aa1319d73a1c5f40debb3e7046f737906ae54edd50bda1a3e28d5a5bb154f3f978047b0b694be13377ad3fa41c32e764af28c490f37d2c1e97f1295b7408d5eca06b7f26938fbe8175880596f58ae02021bc39c1ea03411878729cf18fd1764d491a6f522170823f6adc0608d5f107906c765d07d2db4d6821db21f1d9099c957c360331ed698de3ef9dbea49f86e36da91648236836cf27502c849143bf1659a34987ba18ce7c764fb3043552feb15d4033e52b8aeef5d84557a2774c1b6f60f118f98f941f430c705647909597db04e35758b300db72da4016d5ba036fdb23fbfcb82086d80c232fe98045dc76aee04232d44b9e4a33b4ee31df5fdd439b03eb1b19879b2ab80534493ee7bfc3a368b0b971fe6bd2914bc3eca2f076d30b052fd55e696a11dc2d1c26dde8c9261dee1ba51af423f135ac62b0140e0312ac4a89a1611966cecbc5c8bd0e882aa1d7dc268aa1aa8148b8c4e5cf08f7f5ea4d03a257f1f8f35b3174f31d88335c2f88e165b39b4bd83a5588f181b32f7b7bc01bdd7297d51d0e15d8c3498a729c97337ba187b33a5c692bafbe2266c2bfd17d560f13b932f2d7f348544d9ac8d09c4bfee50ae31527e6f53a60616d33b16f7ab3324d0c20a9eec88eed91ed81250833052a324d7e3dc6603beabc831544a0a2496901d7c579ec660170229954a7e2f6f14be65dab1823ec1df0029389832e9e9693929fbd6bbc3ed8e240739dc55959315e1ea714d8cbc6645f20a7d82f766763a202e7696950c43175d1b6d114414b04ebe77508d769f03f2a72f9a5c3ad9ad1d9b6b5041b009c68a1121b6d85f8866885deb60682f7abb9572c85c440fb3a9c7193ae07e1b143a5f9cd9ba4fc36a798b2278e875cc5abe45787ad9570d1107452e3703ab3a77a34b2c633eca01329505b76b81a306fc1ed678b03cc43da56261c7d92d58e33f22007309ac59cf3b');
   }

    function getCluster1() private pure returns(ISSVClusters.Cluster memory cluster) {
        cluster = ISSVClusters.Cluster({
            validatorCount: 0,
            networkFeeIndex: 0,
            index: 0,
            active: true,
            balance: 0
        });
    }

    function getTokenAmount1() private pure returns(uint256 tokenAmount) {
        tokenAmount = 53460049500000000000;
    }

    function getSsvPayload1() private view returns(SsvPayload memory) {
        SsvOperator[] memory ssvOperators = getUpdatedSsvOperators();
        SsvValidator[] memory ssvValidators = getSsvValidators1();
        ISSVClusters.Cluster memory cluster = getCluster1();
        uint256 tokenAmount = getTokenAmount1();

        return SsvPayload({
            ssvOperators:ssvOperators,
            ssvValidators:ssvValidators,
            cluster:cluster,
            tokenAmount:tokenAmount,
            ssvSlot0: getSsvSlot0()
        });
    }

    function getSsvPayload1WithDuplicateOperatorOwner() private view returns(SsvPayload memory) {
        SsvOperator[] memory ssvOperators = getUpdatedSsvOperators();

        ssvOperators[3] = ssvOperators[2];

        SsvValidator[] memory ssvValidators = getSsvValidators1();
        ISSVClusters.Cluster memory cluster = getCluster1();
        uint256 tokenAmount = getTokenAmount1();

        return SsvPayload({
            ssvOperators:ssvOperators,
            ssvValidators:ssvValidators,
            cluster:cluster,
            tokenAmount:tokenAmount,
            ssvSlot0: getSsvSlot0()
        });
    }

    function getDepositData1() private pure returns(DepositData memory) {
        bytes[] memory signatures = new bytes[](5);
        signatures[0] = bytes(hex'a237e6051904cdb7da5b9c5bad27bafaf68e09547a52801910765a4b6e2a0cbfa13b60d45c7aa349dd77c7031e284c340765b433e7ee98456a07d54421320579cba73565316e2d8125dc8235710047487dcf51dae57639b1f39988ad2607af07');
        signatures[1] = bytes(hex'aadb9ea5736a1abfaa5831d9de69c122a2ee57db1e31704ebd174d7856ca5c712f254bc6f20a2c3ce16392821a31cf7b087cc16e90756562d20d49040332238a8765e95bafc79b2a68f71f6cc4abb7dde469da4be8d31394b032b73e8d7c3dad');
        signatures[2] = bytes(hex'b8a7bb498523b3ddbae9eb11a49a356b5b1420aadd80adc8811e94b010218749f0a08b25b132de57936efa6001d3d979175f0ebfe857cf30302515db09dfa30d071cf8857a5a432cfed4cc5ab7173df40eeb0c763f671d2e9ebed6d49685cb2a');
        signatures[3] = bytes(hex'acfe1607152f55c7f878709b790b88376efa57ebd0d0ea84ae005541a9478880f96c0579e8ac74a4de12b643306c9c9f03e99a7e2ceb51b5216372ef39fddddf42ba17b86a43e9db94004131db29394572d8b3abcd53721fb17a8f5bf85df8bd');
        signatures[4] = bytes(hex'8c30c930d3ea479652abed1977eed6eff7370b1b766108becb03e706e478fb76ebc442e8a68703ba274fbec79a59fedd1717f891153fbb7c0568a85c24aa9a3dc63f389968368556ddc896670f38150df6c25ed6fde9a011d1a01a0ba631d6a7');

        bytes32[] memory depositDataRoots = new bytes32[](5);
        depositDataRoots[0] = bytes32(hex'17130bc95e42fcb72945d1541ba0320eb595201bd18e949850643fc604eee67c');
        depositDataRoots[1] = bytes32(hex'56da945bcdd9acd045052f6665993ff390f671d82b45e01c81a6288b0c1f7f18');
        depositDataRoots[2] = bytes32(hex'46274449c435db805709215e8a0691ab9c568c3597f243abcbebd50c0c690f31');
        depositDataRoots[3] = bytes32(hex'366f2d12d3c297e0b19c8e637793e6ac5780b2ac413fdb0035a1fe2e2cda9551');
        depositDataRoots[4] = bytes32(hex'fb8dfa8b8f5aedefebeee114d9694ec026102ba17fd86c853bbc2d70c4ad59e9');

        return DepositData({
            signatures: signatures,
            depositDataRoots: depositDataRoots
        });
    }

    function getDepositData1DifferentLength() private pure returns(DepositData memory) {
        bytes[] memory signatures = new bytes[](4);
        signatures[0] = bytes(hex'a237e6051904cdb7da5b9c5bad27bafaf68e09547a52801910765a4b6e2a0cbfa13b60d45c7aa349dd77c7031e284c340765b433e7ee98456a07d54421320579cba73565316e2d8125dc8235710047487dcf51dae57639b1f39988ad2607af07');
        signatures[1] = bytes(hex'aadb9ea5736a1abfaa5831d9de69c122a2ee57db1e31704ebd174d7856ca5c712f254bc6f20a2c3ce16392821a31cf7b087cc16e90756562d20d49040332238a8765e95bafc79b2a68f71f6cc4abb7dde469da4be8d31394b032b73e8d7c3dad');
        signatures[2] = bytes(hex'b8a7bb498523b3ddbae9eb11a49a356b5b1420aadd80adc8811e94b010218749f0a08b25b132de57936efa6001d3d979175f0ebfe857cf30302515db09dfa30d071cf8857a5a432cfed4cc5ab7173df40eeb0c763f671d2e9ebed6d49685cb2a');
        signatures[3] = bytes(hex'acfe1607152f55c7f878709b790b88376efa57ebd0d0ea84ae005541a9478880f96c0579e8ac74a4de12b643306c9c9f03e99a7e2ceb51b5216372ef39fddddf42ba17b86a43e9db94004131db29394572d8b3abcd53721fb17a8f5bf85df8bd');

        bytes32[] memory depositDataRoots = new bytes32[](5);
        depositDataRoots[0] = bytes32(hex'17130bc95e42fcb72945d1541ba0320eb595201bd18e949850643fc604eee67c');
        depositDataRoots[1] = bytes32(hex'56da945bcdd9acd045052f6665993ff390f671d82b45e01c81a6288b0c1f7f18');
        depositDataRoots[2] = bytes32(hex'46274449c435db805709215e8a0691ab9c568c3597f243abcbebd50c0c690f31');
        depositDataRoots[3] = bytes32(hex'366f2d12d3c297e0b19c8e637793e6ac5780b2ac413fdb0035a1fe2e2cda9551');
        depositDataRoots[4] = bytes32(hex'fb8dfa8b8f5aedefebeee114d9694ec026102ba17fd86c853bbc2d70c4ad59e9');

        return DepositData({
            signatures: signatures,
            depositDataRoots: depositDataRoots
        });
    }

    function getSsvPayload2() private view returns(SsvPayload memory) {
        SsvOperator[] memory ssvOperators = getUpdatedSsvOperators();
        SsvValidator[] memory ssvValidators = getSsvValidators2();

        return SsvPayload({
            ssvOperators:ssvOperators,
            ssvValidators:ssvValidators,
            cluster:clusterAfter1stRegistation,
            tokenAmount:getTokenAmount1(),
            ssvSlot0: getSsvSlot0()
        });
    }

    function getDepositData2() private pure returns(DepositData memory) {
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = bytes(hex'866a603b7d305c8fae0c431a1d61ef8a957a38ecb81fb9e0c2ae897d0056d2edc68bf0690322e782e86f82c3841ab34816e467c12a8c3b6cd1931c90616c9bb88507247ed70e10d4140c4d6a3c27d9fd802c6af45d973b342403b1f8146c0f72');
        signatures[1] = bytes(hex'a121f2a821df19d761a458096be0488c7d9b73c271e7f4ce768db8a2131b3df195071c8e1cf47c5bafc31884e0e5c1a113ec5601f4284320226c4bea54b675a7c8e2294a0a78dc2740bb07921498e6404f9c2fb4591e24407fc8b4957e23d1e1');

        bytes32[] memory depositDataRoots = new bytes32[](2);
        depositDataRoots[0] = bytes32(hex'0b27827a49b2ad4fa1ef920439fa5d26eba3a338fee363b055f9151caf5f18c7');
        depositDataRoots[1] = bytes32(hex'14d98c3a83b01818d14735badb0d80f8645532c148e52495650ee0ef1234ae3f');

        return DepositData({
            signatures: signatures,
            depositDataRoots: depositDataRoots
        });
    }

    function predictProxyAddress() private view returns(address) {
        address feeDistributor = feeDistributorFactory.predictFeeDistributorAddress(referenceFeeDistributor, clientConfig, referrerConfig);
        return p2pSsvProxyFactory.predictP2pSsvProxyAddress(feeDistributor);
    }

    function test_depositEthAndRegisterValidators_Mainnet() public {
        console.log("test_depositEthAndRegisterValidators_Mainnet started");

        vm.deal(client, 1000 ether);
        vm.startPrank(client);

        DepositData memory depositData1DifferentLength = getDepositData1DifferentLength();
        DepositData memory depositData1 = getDepositData1();
        SsvPayload memory ssvPayload1 = getSsvPayload1();

        vm.expectRevert(abi.encodeWithSelector(
            P2pSsvProxyFactory__DepositDataArraysShouldHaveTheSameLength.selector, 5, 4, 5
        ));
        p2pSsvProxyFactory.depositEthAndRegisterValidators{value: 160 ether}(
            depositData1DifferentLength,
            withdrawalCredentialsAddress,
            ssvPayload1,
            clientConfig,
            referrerConfig
        );

        vm.expectRevert(abi.encodeWithSelector(P2pSsvProxyFactory__EthValueMustBe32TimesValidatorCount.selector, 159 ether));
        p2pSsvProxyFactory.depositEthAndRegisterValidators{value: 159 ether}(
            depositData1,
            withdrawalCredentialsAddress,
            ssvPayload1,
            clientConfig,
            referrerConfig
        );

        p2pSsvProxyFactory.depositEthAndRegisterValidators{value: 160 ether}(
            depositData1,
            withdrawalCredentialsAddress,
            ssvPayload1,
            clientConfig,
            referrerConfig
        );

        vm.stopPrank();

        vm.roll(block.number + 5000);

        vm.startPrank(owner);
        p2pSsvProxyFactory.setMaxSsvTokenAmountPerValidator(MaxSsvTokenAmountPerValidator / 10);
        vm.stopPrank();

        DepositData memory depositData2 = getDepositData2();
        SsvPayload memory ssvPayload2 = getSsvPayload2();

        vm.startPrank(client);
        vm.expectRevert(P2pSsvProxyFactory__MaxSsvTokenAmountPerValidatorExceeded.selector);
        p2pSsvProxyFactory.depositEthAndRegisterValidators{value: 64 ether}(
            depositData2,
            withdrawalCredentialsAddress,
            ssvPayload2,
            clientConfig,
            referrerConfig
        );
        vm.stopPrank();

        vm.startPrank(owner);
        p2pSsvProxyFactory.setMaxSsvTokenAmountPerValidator(MaxSsvTokenAmountPerValidator);
        vm.stopPrank();

        vm.startPrank(client);

        p2pSsvProxyFactory.depositEthAndRegisterValidators{value: 64 ether}(
            depositData2,
            withdrawalCredentialsAddress,
            ssvPayload2,
            clientConfig,
            referrerConfig
        );

        vm.stopPrank();

        console.log("test_depositEthAndRegisterValidators_Mainnet finsihed");
    }

    function registerValidators() private {
        vm.startPrank(owner);
        p2pSsvProxyFactory.setSsvPerEthExchangeRateDividedByWei(SsvPerEthExchangeRateDividedByWei);
        vm.stopPrank();

        SsvPayload memory ssvPayload1 = getSsvPayload1();

        vm.deal(client, 1000 ether);
        vm.startPrank(client);

        uint256 neededEth = p2pSsvProxyFactory.getNeededAmountOfEtherToCoverSsvFees(ssvPayload1.tokenAmount);

        p2pSsvProxyFactory.registerValidators{value: neededEth}(
            ssvPayload1,
            clientConfig,
            referrerConfig
        );

        vm.stopPrank();
    }

    function test_viewFunctions() public {
        console.log("test_viewFunctions started");

        vm.startPrank(owner);
        p2pSsvProxyFactory.setSsvPerEthExchangeRateDividedByWei(SsvPerEthExchangeRateDividedByWei);
        vm.stopPrank();

        SsvPayload memory ssvPayload1 = getSsvPayload1();

        uint256 neededEth = p2pSsvProxyFactory.getNeededAmountOfEtherToCoverSsvFees(ssvPayload1.tokenAmount);

        address proxy1 = predictProxyAddress();
        address feeDistributor = feeDistributorFactory.predictFeeDistributorAddress(referenceFeeDistributor, clientConfig, referrerConfig);

        vm.deal(client, 1000 ether);
        vm.startPrank(client);

        vm.expectEmit();
        emit FeeRecipientAddressUpdated(
            proxy1,
            feeDistributor
        );
        p2pSsvProxyFactory.registerValidators{value: neededEth}(
            ssvPayload1,
            clientConfig,
            referrerConfig
        );
        vm.stopPrank();

        {
        address clientFromProxy = P2pSsvProxy(proxy1).getClient();
        assertEq(clientFromProxy, client);

        address factoryFromProxy = P2pSsvProxy(proxy1).getFactory();
        assertEq(factoryFromProxy, address(p2pSsvProxyFactory));

        address feeDistributorFromProxy = P2pSsvProxy(proxy1).getFeeDistributor();
        assertEq(feeDistributorFromProxy, feeDistributor);

        address ownerFromProxy = P2pSsvProxy(proxy1).owner();
        assertEq(ownerFromProxy, owner);
        }

        vm.startPrank(owner);
        p2pSsvProxyFactory.changeOperator(operator);
        vm.stopPrank();

        {
        address operatorFromProxy = P2pSsvProxy(proxy1).operator();
        assertEq(operatorFromProxy, operator);

        address operatorFromFactory = p2pSsvProxyFactory.operator();
        assertEq(operatorFromFactory, operator);

        address ownerFromFactory = p2pSsvProxyFactory.owner();
        assertEq(ownerFromFactory, owner);

        address[] memory allClientP2pSsvProxies = p2pSsvProxyFactory.getAllClientP2pSsvProxies(client);
        assertEq(allClientP2pSsvProxies[0], proxy1);

        uint64[MAX_ALLOWED_SSV_OPERATOR_IDS] memory ids = p2pSsvProxyFactory.getAllowedSsvOperatorIds(ssvPayload1.ssvOperators[1].owner);
        assertEq(ids[0], ssvPayload1.ssvOperators[1].id);

        address[] memory ssvOperatorOwners = p2pSsvProxyFactory.getAllowedSsvOperatorOwners();
        assertEq(ssvOperatorOwners[1], ssvPayload1.ssvOperators[1].owner);

        address[] memory allProxies = p2pSsvProxyFactory.getAllP2pSsvProxies();
        assertEq(allProxies[0], proxy1);
        }

        {
            address feeDistributorFactoryFromP2pSsvProxyFactory = p2pSsvProxyFactory.getFeeDistributorFactory();
            assertEq(feeDistributorFactoryFromP2pSsvProxyFactory, address(feeDistributorFactory));

            uint256 neededAmountOfEtherToCoverSsvFees = p2pSsvProxyFactory.getNeededAmountOfEtherToCoverSsvFees(ssvPayload1.tokenAmount);
            assertEq(neededAmountOfEtherToCoverSsvFees, (ssvPayload1.tokenAmount * SsvPerEthExchangeRateDividedByWei) / 10**18);

            address referenceFeeDistributorFromFactory = p2pSsvProxyFactory.getReferenceFeeDistributor();
            assertEq(referenceFeeDistributorFromFactory, referenceFeeDistributor);

            address referenceP2pSsvProxyFromFactory = p2pSsvProxyFactory.getReferenceP2pSsvProxy();
            assertEq(referenceP2pSsvProxyFromFactory, referenceP2pSsvProxy);

            uint256 ssvPerEthExchangeRateDividedByWeiFromFactory = p2pSsvProxyFactory.getSsvPerEthExchangeRateDividedByWei();
            assertEq(ssvPerEthExchangeRateDividedByWeiFromFactory, SsvPerEthExchangeRateDividedByWei);

            bytes4[] memory selectors = new bytes4[](1);
            selectors[0] = ISSVClusters.withdraw.selector;

            bool isOperatorSelectorAllowedFromFactoryBefore = p2pSsvProxyFactory.isOperatorSelectorAllowed(selectors[0]);
            assertEq(isOperatorSelectorAllowedFromFactoryBefore, false);

            vm.startPrank(owner);
            p2pSsvProxyFactory.setAllowedSelectorsForOperator(selectors);
            vm.stopPrank();

            bool isOperatorSelectorAllowedFromFactoryAfter = p2pSsvProxyFactory.isOperatorSelectorAllowed(selectors[0]);
            assertEq(isOperatorSelectorAllowedFromFactoryAfter, true);

            bool isClientSelectorAllowedFromFactoryBefore = p2pSsvProxyFactory.isClientSelectorAllowed(selectors[0]);
            assertEq(isClientSelectorAllowedFromFactoryBefore, false);

            vm.startPrank(owner);
            p2pSsvProxyFactory.setAllowedSelectorsForClient(selectors);
            vm.stopPrank();

            bool isClientSelectorAllowedFromFactoryAfter = p2pSsvProxyFactory.isClientSelectorAllowed(selectors[0]);
            assertEq(isClientSelectorAllowedFromFactoryAfter, true);

            vm.startPrank(owner);
            p2pSsvProxyFactory.removeAllowedSelectorsForClient(selectors);
            vm.stopPrank();

            isClientSelectorAllowedFromFactoryAfter = p2pSsvProxyFactory.isClientSelectorAllowed(selectors[0]);
            assertEq(isClientSelectorAllowedFromFactoryAfter, false);
        }

        console.log("test_viewFunctions finsihed");
    }

    function test_setFeeRecipientAddress() public {
        console.log("test_setFeeRecipientAddress started");

        vm.startPrank(owner);
        p2pSsvProxyFactory.setSsvPerEthExchangeRateDividedByWei(SsvPerEthExchangeRateDividedByWei);
        vm.stopPrank();

        SsvPayload memory ssvPayload1 = getSsvPayload1();

        uint256 neededEth = p2pSsvProxyFactory.getNeededAmountOfEtherToCoverSsvFees(ssvPayload1.tokenAmount);

        address proxy1 = predictProxyAddress();
        address feeDistributor = feeDistributorFactory.predictFeeDistributorAddress(referenceFeeDistributor, clientConfig, referrerConfig);

        vm.deal(client, 1000 ether);
        vm.startPrank(client);

        vm.expectEmit();
        emit FeeRecipientAddressUpdated(
            proxy1,
            feeDistributor
        );
        p2pSsvProxyFactory.registerValidators{value: neededEth}(
            ssvPayload1,
            clientConfig,
            referrerConfig
        );
        vm.stopPrank();

        vm.startPrank(owner);

        vm.expectEmit();
        emit FeeRecipientAddressUpdated(
            proxy1,
            client
        );
        P2pSsvProxy(proxy1).setFeeRecipientAddress(client);
        vm.stopPrank();

        console.log("test_setFeeRecipientAddress finsihed");
    }

    function test_setReferenceFeeDistributor() public {
        console.log("test_setReferenceFeeDistributor started");

        vm.startPrank(owner);
        p2pSsvProxyFactory.setSsvPerEthExchangeRateDividedByWei(SsvPerEthExchangeRateDividedByWei);
        vm.stopPrank();

        SsvPayload memory ssvPayload1 = getSsvPayload1();

        uint256 neededEth = p2pSsvProxyFactory.getNeededAmountOfEtherToCoverSsvFees(ssvPayload1.tokenAmount);

        vm.deal(client, 1000 ether);
        vm.startPrank(client);
        address proxy1 = p2pSsvProxyFactory.registerValidators{value: neededEth}(
            ssvPayload1,
            clientConfig,
            referrerConfig
        );
        vm.stopPrank();

        address referenceFeeDistributor2 = 0x6091767Be457a5A7f7d368dD68Ebf2f416728d97;
        vm.startPrank(owner);
        p2pSsvProxyFactory.setReferenceFeeDistributor(referenceFeeDistributor2);
        vm.stopPrank();

        address feeDistributor2 = feeDistributorFactory.predictFeeDistributorAddress(referenceFeeDistributor2, clientConfig, referrerConfig);
        address proxy2 = p2pSsvProxyFactory.predictP2pSsvProxyAddress(feeDistributor2);

        assertNotEq(proxy1, proxy2);

        console.log("test_setReferenceFeeDistributor finsihed");
    }

    function test_settersAndRemovers() public {
        console.log("test_settersAndRemovers started");

        vm.startPrank(owner);
        p2pSsvProxyFactory.setSsvPerEthExchangeRateDividedByWei(SsvPerEthExchangeRateDividedByWei);
        vm.stopPrank();

        SsvPayload memory ssvPayload1 = getSsvPayload1();

        uint256 neededEth = p2pSsvProxyFactory.getNeededAmountOfEtherToCoverSsvFees(ssvPayload1.tokenAmount);

        address feeDistributor = 0x6bCBFF73A652B6cB1852c4d85cc34894F5120e28;
        address proxy1 = p2pSsvProxyFactory.predictP2pSsvProxyAddress(feeDistributor);
        assertEq(proxy1.code.length, 0);

        vm.startPrank(owner);
        p2pSsvProxyFactory.createP2pSsvProxy(feeDistributor);
        vm.stopPrank();

        assertNotEq(proxy1.code.length, 0);

        vm.deal(client, 1000 ether);
        vm.startPrank(client);
        p2pSsvProxyFactory.registerValidators{value: neededEth}(
            ssvPayload1,
            clientConfig,
            referrerConfig
        );
        vm.stopPrank();

        address[] memory ssvOperatorOwners = new address[](2);
        ssvOperatorOwners[0] = 0x8D174A0a34A244C4E2B6568f373dA136a2ffafc8;
        ssvOperatorOwners[1] = 0xf2659Cc196829c6676B1E0E1a71A8797ceC6778A;

        vm.startPrank(owner);
        p2pSsvProxyFactory.setAllowedSsvOperatorOwners(ssvOperatorOwners);
        p2pSsvProxyFactory.setSsvOperatorIds([uint64(0), 0, 0, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0], ssvOperatorOwners[0]);
        p2pSsvProxyFactory.setSsvOperatorIds([uint64(0), 0, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], ssvOperatorOwners[1]);
        vm.stopPrank();

        vm.startPrank(ssvOperatorOwners[0]);
        p2pSsvProxyFactory.setSsvOperatorIds([uint64(37), 38, 39, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        vm.stopPrank();

        vm.startPrank(ssvOperatorOwners[1]);
        p2pSsvProxyFactory.setSsvOperatorIds([uint64(45), 0, 44, 0, 43, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        p2pSsvProxyFactory.clearSsvOperatorIds();
        p2pSsvProxyFactory.clearSsvOperatorIds();
        vm.stopPrank();

        vm.startPrank(owner);
        p2pSsvProxyFactory.removeAllowedSsvOperatorOwners(ssvOperatorOwners);
        vm.stopPrank();

        vm.startPrank(ssvOperatorOwners[1]);
        vm.expectRevert(abi.encodeWithSelector(P2pSsvProxyFactory__NotAllowedSsvOperatorOwner.selector, ssvOperatorOwners[1]));
        p2pSsvProxyFactory.setSsvOperatorIds([uint64(45), 0, 44, 0, 43, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        vm.stopPrank();

        console.log("test_settersAndRemovers finsihed");
    }

    function test_removeValidators() public {
        console.log("test_removeValidators started");

        vm.startPrank(owner);
        p2pSsvProxyFactory.setSsvPerEthExchangeRateDividedByWei(SsvPerEthExchangeRateDividedByWei);
        vm.stopPrank();

        SsvPayload memory ssvPayload1 = getSsvPayload1();

        uint256 neededEth = p2pSsvProxyFactory.getNeededAmountOfEtherToCoverSsvFees(ssvPayload1.tokenAmount);

        vm.deal(client, 1000 ether);
        vm.startPrank(client);
        address proxy1 = p2pSsvProxyFactory.registerValidators{value: neededEth}(
            ssvPayload1,
            clientConfig,
            referrerConfig
        );
        vm.stopPrank();

        bytes[] memory _pubkeys = new bytes[](2);
        _pubkeys[0] = ssvPayload1.ssvValidators[1].pubkey;
        _pubkeys[1] = ssvPayload1.ssvValidators[3].pubkey;
        uint64[] memory _operatorIds = new uint64[](4);
        _operatorIds[0] = ssvPayload1.ssvOperators[0].id;
        _operatorIds[1] = ssvPayload1.ssvOperators[1].id;
        _operatorIds[2] = ssvPayload1.ssvOperators[2].id;
        _operatorIds[3] = ssvPayload1.ssvOperators[3].id;
        ISSVNetwork.Cluster[] memory _clusters = new ISSVNetwork.Cluster[](2);
        _clusters[0] = clusterAfter1stRegistation;
        _clusters[1] = clusterAfter1stRegistation;
        _clusters[1].validatorCount = 4;

        ISSVNetwork.Cluster memory clusterAfterRemoval = clusterAfter1stRegistation;
        clusterAfterRemoval.validatorCount = 3;

        vm.startPrank(owner);

        vm.expectEmit();
        emit ValidatorRemoved(
            proxy1,
            _operatorIds,
            ssvPayload1.ssvValidators[3].pubkey,
            clusterAfterRemoval
        );

        P2pSsvProxy(proxy1).removeValidators(_pubkeys, _operatorIds, _clusters);
        vm.stopPrank();

        console.log("test_removeValidators finsihed");
    }

    function test_liquidateAndReactivate() public {
        console.log("test_liquidateAndReactivate started");

        vm.startPrank(owner);
        p2pSsvProxyFactory.setSsvPerEthExchangeRateDividedByWei(SsvPerEthExchangeRateDividedByWei);
        vm.stopPrank();

        SsvPayload memory ssvPayload1 = getSsvPayload1();

        uint256 neededEth = p2pSsvProxyFactory.getNeededAmountOfEtherToCoverSsvFees(ssvPayload1.tokenAmount);

        vm.deal(client, 1000 ether);
        vm.startPrank(client);
        address proxy1 = p2pSsvProxyFactory.registerValidators{value: neededEth}(
            ssvPayload1,
            clientConfig,
            referrerConfig
        );
        vm.stopPrank();

        uint64[] memory _operatorIds = new uint64[](4);
        _operatorIds[0] = ssvPayload1.ssvOperators[0].id;
        _operatorIds[1] = ssvPayload1.ssvOperators[1].id;
        _operatorIds[2] = ssvPayload1.ssvOperators[2].id;
        _operatorIds[3] = ssvPayload1.ssvOperators[3].id;
        ISSVNetwork.Cluster[] memory _clusters = new ISSVNetwork.Cluster[](1);
        _clusters[0] = clusterAfter1stRegistation;

        ISSVClusters.Cluster memory clusterAfterLiquidation = ISSVClusters.Cluster({
            validatorCount: 5,
            networkFeeIndex: 0,
            index: 0,
            active: false,
            balance: 0
        });

        uint256 ssvTokenBalanceBefore = ssvToken.balanceOf(proxy1);

        vm.startPrank(owner);

        vm.expectEmit();
        emit ClusterLiquidated(
            proxy1,
            _operatorIds,
            clusterAfterLiquidation
        );

        P2pSsvProxy(proxy1).liquidate(_operatorIds, _clusters);
        vm.stopPrank();

        uint256 ssvTokenBalanceAfter = ssvToken.balanceOf(proxy1);

        assertEq(ssvTokenBalanceAfter - ssvTokenBalanceBefore, ssvPayload1.tokenAmount);

        uint256 ssvOwnerTokenBalanceBefore = ssvToken.balanceOf(owner);

        vm.expectRevert(abi.encodeWithSelector(OwnableBase__CallerNotOwner.selector, address(this), owner));
        P2pSsvProxy(proxy1).withdrawSSVTokens(owner, ssvPayload1.tokenAmount);

        vm.startPrank(owner);
        P2pSsvProxy(proxy1).withdrawSSVTokens(owner, ssvPayload1.tokenAmount);
        vm.stopPrank();

        uint256 ssvOwnerTokenBalanceAfter = ssvToken.balanceOf(owner);

        assertEq(ssvOwnerTokenBalanceAfter - ssvOwnerTokenBalanceBefore, ssvPayload1.tokenAmount);

        vm.startPrank(owner);

        ssvToken.transfer(proxy1, ssvPayload1.tokenAmount);
        _clusters[0] = clusterAfterLiquidation;

        vm.expectEmit();
        emit ClusterReactivated(
            proxy1,
            _operatorIds,
            clusterAfter1stRegistation
        );

        P2pSsvProxy(proxy1).reactivate(ssvPayload1.tokenAmount, _operatorIds, _clusters);
        vm.stopPrank();

        _clusters[0] = clusterAfter1stRegistation;
        deal(address(ssvToken), address(this), 50000 ether);

        ssvToken.transfer(proxy1, 42 ether);

        ISSVClusters.Cluster memory clusterAfterDeposit = clusterAfter1stRegistation;
        clusterAfterDeposit.balance += 42 ether;

        vm.expectEmit();
        emit ClusterDeposited(
            proxy1,
            _operatorIds,
            42 ether,
            clusterAfterDeposit
        );

        P2pSsvProxy(proxy1).depositToSSV(42 ether, _operatorIds, _clusters);

        console.log("test_liquidateAndReactivate finsihed");
    }

    function test_registerValidators() public {
        console.log("test_registerValidators started");

        registerValidators();

        console.log("test_registerValidators finsihed");
    }

    function test_DuplicateOperatorOwner() public {
        console.log("test_DuplicateOperatorOwner started");

        vm.startPrank(owner);
        p2pSsvProxyFactory.setSsvPerEthExchangeRateDividedByWei(SsvPerEthExchangeRateDividedByWei);
        vm.stopPrank();

        SsvPayload memory ssvPayload1 = getSsvPayload1WithDuplicateOperatorOwner();

        vm.deal(client, 1000 ether);
        vm.startPrank(client);

        uint256 neededEth = p2pSsvProxyFactory.getNeededAmountOfEtherToCoverSsvFees(ssvPayload1.tokenAmount);

        vm.expectRevert(abi.encodeWithSelector(
            P2pSsvProxyFactory__DuplicateOperatorOwnersNotAllowed.selector,
            ssvPayload1.ssvOperators[3].owner,
            ssvPayload1.ssvOperators[3].id,
            ssvPayload1.ssvOperators[2].id
        ));
        p2pSsvProxyFactory.registerValidators{value: neededEth}(
            ssvPayload1,
            clientConfig,
            referrerConfig
        );

        vm.stopPrank();

        console.log("test_DuplicateOperatorOwner finsihed");
    }

    function test_NewClientSelectors() public {
        console.log("test_NewClientSelectors started");

        registerValidators();

        bytes memory callData = abi.encodeCall(ISSVClusters.withdraw, (operatorIds, 42, clusterAfter1stRegistation));

        vm.startPrank(client);
        (bool success1, bytes memory data1) = proxyAddress.call(callData);
        vm.stopPrank();

        assertFalse(success1);
        assertEq(data1, abi.encodeWithSelector(P2pSsvProxy__SelectorNotAllowed.selector, client, ISSVClusters.withdraw.selector));

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = ISSVClusters.withdraw.selector;

        vm.startPrank(owner);
        p2pSsvProxyFactory.setAllowedSelectorsForClient(selectors);
        vm.stopPrank();

        vm.startPrank(client);
        (bool success2, bytes memory data2) = proxyAddress.call(callData);
        vm.stopPrank();

        assertTrue(success2);
        assertEq(data2, bytes(''));

        console.log("test_NewClientSelectors finished");
    }

    function test_NewOperatorSelectors() public {
        console.log("test_NewOperatorSelectors started");

        registerValidators();

        vm.startPrank(owner);
        p2pSsvProxyFactory.changeOperator(operator);
        vm.stopPrank();

        bytes memory callData = abi.encodeCall(ISSVClusters.withdraw, (operatorIds, 42, clusterAfter1stRegistation));

        vm.startPrank(operator);
        (bool success1, bytes memory data1) = proxyAddress.call(callData);
        vm.stopPrank();

        assertFalse(success1);
        assertEq(data1, abi.encodeWithSelector(P2pSsvProxy__SelectorNotAllowed.selector, operator, ISSVClusters.withdraw.selector));

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = ISSVClusters.withdraw.selector;

        vm.startPrank(owner);
        p2pSsvProxyFactory.setAllowedSelectorsForOperator(selectors);
        vm.stopPrank();

        vm.startPrank(operator);
        (bool success2, bytes memory data2) = proxyAddress.call(callData);
        vm.stopPrank();

        assertTrue(success2);
        assertEq(data2, bytes(''));

        vm.startPrank(owner);
        p2pSsvProxyFactory.removeAllowedSelectorsForOperator(selectors);
        vm.stopPrank();

        vm.startPrank(operator);
        (bool success3, bytes memory data3) = proxyAddress.call(callData);
        vm.stopPrank();

        assertFalse(success3);
        assertEq(data3, abi.encodeWithSelector(P2pSsvProxy__SelectorNotAllowed.selector, operator, ISSVClusters.withdraw.selector));

        console.log("test_NewOperatorSelectors finished");
    }

    function test_NewOwnerSelectors() public {
        console.log("test_NewOwnerSelectors started");

        registerValidators();

        bytes memory callData = abi.encodeCall(ISSVClusters.withdraw, (operatorIds, 42, clusterAfter1stRegistation));

        vm.startPrank(owner);
        (bool success1, bytes memory data1) = proxyAddress.call(callData);
        vm.stopPrank();

        assertTrue(success1);
        assertEq(data1, bytes(''));

        console.log("test_NewOwnerSelectors finished");
    }

    function test_WithdrawSsvTokens() public {
        console.log("test_WithdrawSsvTokens started");

        registerValidators();

        ISSVClusters.Cluster[] memory clusters = new ISSVClusters.Cluster[](1);
        clusters[0] = clusterAfter1stRegistation;

        uint256 proxyBalanceBefore = ssvToken.balanceOf(proxyAddress);

        uint256 tokenAmount = 42;

        vm.startPrank(owner);
        P2pSsvProxy(proxyAddress).withdrawFromSSV(tokenAmount, operatorIds, clusters);
        vm.stopPrank();

        uint256 proxyBalanceAfter = ssvToken.balanceOf(proxyAddress);

        assertEq(proxyBalanceAfter - proxyBalanceBefore, tokenAmount);

        uint256 ownerBalanceBefore = ssvToken.balanceOf(owner);

        vm.startPrank(owner);
        P2pSsvProxy(proxyAddress).withdrawSSVTokens(owner, tokenAmount);
        vm.stopPrank();

        uint256 ownerBalanceAfter = ssvToken.balanceOf(owner);

        assertEq(ownerBalanceAfter - ownerBalanceBefore, tokenAmount);

        console.log("test_WithdrawSsvTokens finished");
    }

    function test_DepositToSSV() public {
        console.log("test_DepositToSSV started");

        registerValidators();

        uint256 factoryBalanceBefore = ssvToken.balanceOf(address(p2pSsvProxyFactory));

        uint256 tokenAmount = 42;

        ISSVClusters.Cluster memory clusterAfterDeposit = ISSVClusters.Cluster({
            validatorCount: clusterAfter1stRegistation.validatorCount,
            networkFeeIndex: clusterAfter1stRegistation.networkFeeIndex,
            index: clusterAfter1stRegistation.index,
            active: true,
            balance: clusterAfter1stRegistation.balance + tokenAmount
        });

        vm.startPrank(operator);
        vm.expectRevert(abi.encodeWithSelector(
            OwnableBase__CallerNotOwner.selector, operator, owner
        ));
        p2pSsvProxyFactory.depositToSSV(proxyAddress, tokenAmount, operatorIds, clusterAfter1stRegistation);
        vm.stopPrank();

        vm.startPrank(owner);
        vm.expectEmit();
        emit ClusterDeposited(
            proxyAddress,
            operatorIds,
            tokenAmount,
            clusterAfterDeposit
        );
        p2pSsvProxyFactory.depositToSSV(proxyAddress, tokenAmount, operatorIds, clusterAfter1stRegistation);
        vm.stopPrank();

        uint256 factoryBalanceAfter = ssvToken.balanceOf(address(p2pSsvProxyFactory));
        assertEq(factoryBalanceBefore - factoryBalanceAfter, tokenAmount);

        console.log("test_DepositToSSV finished");
    }

    function test_bulkExitValidator() public {
        console.log("test_bulkExitValidator started");

        vm.startPrank(owner);
        p2pSsvProxyFactory.changeOperator(operator);
        vm.stopPrank();

        vm.startPrank(owner);
        p2pSsvProxyFactory.setSsvPerEthExchangeRateDividedByWei(SsvPerEthExchangeRateDividedByWei);
        vm.stopPrank();

        SsvPayload memory ssvPayload1 = getSsvPayload1();

        uint256 neededEth = p2pSsvProxyFactory.getNeededAmountOfEtherToCoverSsvFees(ssvPayload1.tokenAmount);

        vm.deal(client, 1000 ether);
        vm.startPrank(client);
        address proxy1 = p2pSsvProxyFactory.registerValidators{value: neededEth}(
            ssvPayload1,
            clientConfig,
            referrerConfig
        );
        vm.stopPrank();

        bytes[] memory _pubkeys = new bytes[](2);
        _pubkeys[0] = ssvPayload1.ssvValidators[1].pubkey;
        _pubkeys[1] = ssvPayload1.ssvValidators[3].pubkey;
        uint64[] memory _operatorIds = new uint64[](4);
        _operatorIds[0] = ssvPayload1.ssvOperators[0].id;
        _operatorIds[1] = ssvPayload1.ssvOperators[1].id;
        _operatorIds[2] = ssvPayload1.ssvOperators[2].id;
        _operatorIds[3] = ssvPayload1.ssvOperators[3].id;
        ISSVNetwork.Cluster[] memory _clusters = new ISSVNetwork.Cluster[](2);
        _clusters[0] = clusterAfter1stRegistation;
        _clusters[1] = clusterAfter1stRegistation;
        _clusters[1].validatorCount = 4;

        vm.startPrank(owner);

        vm.expectEmit();
        emit ValidatorExited(
            proxy1,
            _operatorIds,
            ssvPayload1.ssvValidators[1].pubkey
        );

        P2pSsvProxy(proxy1).bulkExitValidator(_pubkeys, _operatorIds);
        vm.stopPrank();

        vm.startPrank(operator);

        vm.expectEmit();
        emit ValidatorExited(
            proxy1,
            _operatorIds,
            ssvPayload1.ssvValidators[1].pubkey
        );

        P2pSsvProxy(proxy1).bulkExitValidator(_pubkeys, _operatorIds);
        vm.stopPrank();

        vm.startPrank(client);

        vm.expectEmit();
        emit ValidatorExited(
            proxy1,
            _operatorIds,
            ssvPayload1.ssvValidators[1].pubkey
        );

        P2pSsvProxy(proxy1).bulkExitValidator(_pubkeys, _operatorIds);
        vm.stopPrank();

        vm.startPrank(nobody);

        vm.expectRevert(abi.encodeWithSelector(P2pSsvProxy__CallerNeitherOperatorNorOwnerNorClient.selector, nobody));

        P2pSsvProxy(proxy1).bulkExitValidator(_pubkeys, _operatorIds);
        vm.stopPrank();

        console.log("test_bulkExitValidator finsihed");
    }

    function test_withdrawAllSSVTokensToFactory() public {
        console.log("test_withdrawAllSSVTokensToFactory started");

        vm.startPrank(owner);
        p2pSsvProxyFactory.changeOperator(operator);
        vm.stopPrank();

        registerValidators();

        ISSVClusters.Cluster[] memory clusters = new ISSVClusters.Cluster[](1);
        clusters[0] = clusterAfter1stRegistation;

        uint256 proxyBalanceBefore = ssvToken.balanceOf(proxyAddress);

        uint256 tokenAmount = 42;

        vm.startPrank(owner);
        P2pSsvProxy(proxyAddress).withdrawFromSSV(tokenAmount, operatorIds, clusters);
        vm.stopPrank();

        uint256 proxyBalanceAfter = ssvToken.balanceOf(proxyAddress);

        assertEq(proxyBalanceAfter - proxyBalanceBefore, tokenAmount);

        vm.startPrank(nobody);

        vm.expectRevert(abi.encodeWithSelector(P2pSsvProxy__CallerNeitherOperatorNorOwner.selector, nobody, operator, owner));

        P2pSsvProxy(proxyAddress).withdrawAllSSVTokensToFactory();
        vm.stopPrank();

        uint256 factoryBalanceBefore = ssvToken.balanceOf(address(p2pSsvProxyFactory));

        vm.startPrank(owner);
        P2pSsvProxy(proxyAddress).withdrawAllSSVTokensToFactory();
        vm.stopPrank();

        uint256 factoryBalanceAfter = ssvToken.balanceOf(address(p2pSsvProxyFactory));

        assertEq(factoryBalanceAfter - factoryBalanceBefore, tokenAmount);

        console.log("test_withdrawAllSSVTokensToFactory finished");
    }
}
