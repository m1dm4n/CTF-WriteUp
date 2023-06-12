import ecdsa # https://pypi.org/project/ecdsa/
import os

flag = os.environ.get('FLAG', 'SEE{HZHFnavcAtDyOSWvXCSCzJDolxjuSFxfStWvCkXQRyGTRmBP}').encode()
sk = ecdsa.SigningKey.generate()
for nibble in flag.hex():
    signature = sk.sign(flag + nibble.encode())
    print(int(signature.hex()[:48], 16), int(signature.hex()[48:], 16))
    print(signature)
    exit()
    # print(flag + nibble.encode())

# Code ends here. The output is printed below.
sus = '''
04a22664841747a475192a7f9b6461404c0f85c46810d00d1a18249338e5bb58fe32e6580e6aab74dad040e1e7ae0a2d
4992c6691ae1e326f5038d050bce13d5007625c3c694a86dc9a75748f395ae80b5d904b6464f0e17b2df17e6b9f540ee
836b146003baaf00b28403ca52b7df2d949350cf4e57b7e9f981b6ee9293c93d44977f102b5bd4000d93890ebfff2d28
5e7d2389cb92df48845cf3d70a172e458de9456743964568c2532f080ea5b4ba70301b27f5d9019f5d0ac4aafd2147af
1cf28514e763cf6494814e0d64d32bd20ce99a983e88dc66225aaa4246c58ab6f33a2bfe441e023582b47937ac8d15a4
1a1980d999797b5af80d4f550d741708352f738c137f8ca6e1fd9dd3b70fa75f800f865b6b5098fb95c62ab40a80594f
83b70fc96da176c34f616a48be43ebc22b090545a52b972cc784d55c79996ef842493514a6969db7c5d34b9ef6fcd28e
99c5d66a1f7f79d5b194397af66a347b7cba9dc5d327424aea71bc82fba1bbf5d50acd57e6eea4fa366a542f1a91e350
37f606bfdc2004293292509364f154173a1c13aea5f6dd75be8b5cb0343e92c8efc405e7956b73132afa80d327521a8b
012a666c3dbf7a64760acf459fd4ad4de7a235ee8866c3810227c8f7cbcddda79130c46b820bff9521965dfe44de32af
ceb8fdf5acaf767a76f40ae6112b5c402a2e4e7713631e4c51e963fa61b193fd8ef0fbcbf088e5b525d1d808c5d094dd
71b1a7e5b7816b1de309daa88a8a3883a37d28650532ecbc3f462b005b353266011bdf3d642d78822c8c7299449f1f22
02caf72b6060b761d23c9bdfd4e9296a34bfd0a364eba5a81ae842a117bdd82c28ac8c692911b7d3eedbf3c543d0f48d
b959a90d2aab7a2be3684b69328d35ed9694d9df0eb4ea6e6938c806838d0db6b76718b9e7fc4268c14c17246f499af9
03b422faff6fd1de0dff181977560def1bef40ee307957d15039b06c202bc5827eba1d0e2c5027051fb5dc093bded056
fa5f0046485ea006d5917d353d3cba2010c3b5edbe87352f7450dd155c15e38de1d990be4754c5c0ff24d37a8f01af92
f027161939478e23ac9b99d56e37a0cdd76175a42892f8d7cb0dcc84964663d672c9f23812d016d445ff5c7589725c6d
30b8757465a5ec8801a5a190eb296d7d2c9ea3b1eb2c62f6062a0a8b5115f30c054cb0d5eeaba480dabfb3c5c70abef0
889087215877cabd0c743f5864306db81fa46e91eac31b759b0d23afc036235d265c609e37117b9d15266ce8ecc5db2b
9c76eae7ec44540bd41c06ba9c25b4734c9bbf68880494a38e0b118fca93677fa5770b98c0b982245a207880036e6445
2bd29f6aa55103be42b16e394a1190a03f8a22b7b7162a5d03c0423a19de47b4b8167bc330690f36db02ef5377624c80
c9b933108fad16ffd1275ea14e4b506d9c9c03df4287f99a71c09402c3a11c19932ad14af8468a84aedd8615a762d366
2e564b6e2730d220a65de2899ec7a99056c3d8e89f0178b5e974483bcc9b5949f69908777f7332bb4fe84d431e8a5a35
2f687205c31b07820a872e2a3d4e6897561ee3873086b445570a66b13232ade40e38397b648a5cac7a9a324664ece3bf
2dca9b0a9e96472b18119921a681d23d2ec3acacd1b9c0a011e23ca24407808be25e04edcbc736b9b11b6a167a2d297a
b2781278a3acd8768ca8ba1ad698a3b775c330df9a7837d18f9796cd838e5714e461f1bbfd1d3af9230c05ea33bc5555
191447109bb7de900a70e06170e492fd84d908fde7ccd2a5ed6a28c1860e655958d2f54e4638a54cbebbd35a61b528dc
54e0e6509a899baf44574eaa7d302bf00e5edfd8b0d0fa62f74524bf92bea63384773489c69e64b4b757afc9da0ecda4
941d9cb5676e366157d8bd6c92b7687539acb7a06bc611f8ad64871f0e6a598385957517aeb9972b719477bbdb31865f
1741225d735cc11377c31e8976a269473d66d8f788f34822cae720cd82f0e99af50807d1edb7513ba14efc097183d192
f5568fc82c2ca245465533f9b98bb537c9bc8e2e050d00cdf431e8acf6ed5c69b88f93760cb7fe85128a22db83242ba4
d00c1c38ff9cd6e15846aac2e821b9d60846a96d0688f86f40ea3178030868579300e2c0aa9cf9ae373ae9f817fe7ae5
76fb8669a5694795efaa9b4e38c0a306112054c891f9f871a80b6caec231f35b45c0c6ca8f64423861a5d5d09362af51
cffe394dd32e1bd6c71d300412f6551512a9eb71be7eb4b53c702caae94ae8673bf95cb7e76a0bb06e345e7e35305efa
cc82ce7885a5ac4bc08bdbd13976e3cd3b2a3f439180a329e826275e3dee8386720bf28d75596c289b5bc0b9d364eef9
4f4eb4b9bb6c6deaf1173763dbd1518079096d8863a4140dca9c01693ae4bfaab6f125e0ed5a5f20200b8c1a86e58ef8
9cad001be5d25df58a5a804ca97d9e6c7f32d6779fc020bf68727a83548382c5dc4e12359e0914cf7fca879c60fce06d
1f7091b011dfdd1ea0dcb6071f85d5c75642e37517d5263d4b468490496f90abb26e02307aa54d3d4dfde6d80626d933
7a05a981041f8e406fc69a5569c5aa2c2fa8a4c6445e3bd974a19f9fb3720cb5218c79e5eb586bfc3915d0e7ca7a9638
71b8b89846f6849a17cd6258695790f7c71945e0c6b8fd3f297809ad61ddd9f73f8ec4538e45d1d420f328fefd71fd39
d8397c87bd54c91a060d0565ff0f6edc0af0287889cd7a03ac321ea9ae1999f370ee8881b2a01b924f4fbc199cf1d868
5b848e0310b6d652310686af9cbbc6d08f42e37eb83c3c0cec22e643f859c30fc7bbeb8c1fe4e16c8dcf9e325a685a7a
4cc8713a14a5a074ecc112e22192bb162e1d5ea303939dbf2bbb9620da0ff9eb326fb5b30c7c133283a7949230ee7177
fa7e00b2da873ad104a50df8639ee6e8e702e256fd4a8ebbb25bde28988750eefcef91d4ec891458f3e700fef132071f
1fdfd4432de9d3647a194cf8d66b3d8a5e3eac5bb1e832b366ed37b4b7875fa6346b1b65bb3f068c61358ad7b7e5ee5e
0d660198e6c811a34136dc087693e81ebbd5877c722a7624ddb682043e5d24c8cf892f13b2cf2383f476f12e68bd94b5
e8f9d1f42b54c76836bae42b05bba24ffcdd0dd935380b615223a0c6ca1569a448d74cbb78e47bca635dade3e802c8a5
04a21057c034f7cb9eff39935f464aa5d4dc027b9d5da05ee5f097f12f40a4046f87683ad1638e1e05e61246ee178fbd
cabf588910bce6d41552ac5addb00f196f90c809dc6856f8e8c7490338b98bc423d2cf42c3e3faa73ab171a5a8544433
d61eeaa195eaa6970dc99e4e0ed779ee0e450f4b73917b6fd00f4bd99b26a0bb05313cdc8915d17d7b0d9942410658af
c758b4cf5847593c4cb4e356ec865e8797d74a564cf9ad1549feb4d8439e8598d0b69cd44c3267d36c1d7317303e2aa1
bd21290aee61dd300f3850b567114c8f5a1b6f8b170711b8b79f225a04961c5c39903d100a8725025da33922beba9098
a832c1f4b54699f59adff2dc5d9401888ef48eb1e3dee75d6b24334db5d8cdbe17cc87131fcfeb2fc59a084a817047a1
9251d8c0e198b84bb52e656388a4a5fc7e487dd777effa80cce8f0a9feab8b5a96bffeb73f36984c16fbb1214e2cfe65
8e2bc98948c3d0989ef1fcb26620a383a41414e55b5844e6e61e50335c18c097c1850c78acd776ffe4d35194227fb358
f18f9004efa7d5c6201faa99481df0870403f0952beffcecf9bae9eb05be06e777c83bd3fe30ba8666d72292c9f6c093
a07f86f2a093ca8d6fdbc63cb56d3527e6c85225fb77f86efea0dc1550333e7b5abcb49368c60a70ef4cf8456600b73e
a520893f94bc749b07d25d8bd1185105c001f12f4e0004733f6b1ff2197925941891f343f3eaa97bfcd461776b46217d
739c2f2c68b83569cccfb8d9178ac5e5299723fedae515d6df245ad5a0964b91f9a5a6e869c7ef57598fd33757db51a3
cb59854d3b20c9f5d432e205af140bfbd34ccee0b579f67e6ceefd91e64815df1e84969a9ee2a57bd6e559d7ef9ec3c9
1b9556ba0691912615c25a08eebb0b56e46ee639c56ef2b979322e5cbc797c9c83fa59b83c5e9e45b9b7eb51eaa1ed77
0f49b18563052f9b64ebbc1a9e0fa1e5685e09c8bd266e4231e42fd25ac74f7bea9d4decd17bd9b5c9b8c808a3751612
77f08e003539e15a5a5f860cb8e9cd42ae239c9c2c7bb7d7e094b15834c86f70e4b8bb22fde71ddb4a6916b2e9725d00
5073b22c6ac1c3171e01bfaaf0ab55b2d8be72fc259efe5c36bc1cdfa2a15db2e682411d4289bd66090417aa9893c46a
a11eadfd3a5c22820b1bc815088bebf74804b8479a77a8b72641a2743f6a1401038006cb90c777d7f29f42f519ef1545
e06f918ac5e068884627b2b30968e5241c8f7be6a66c92357f905eb734c7d2a8e0da5e2b355749dfa684173aa0cfaba7
ddcfe5abc02ba60668d6d87420fb1d74fc54b97707ff01cf2a0200ddf2eb708e40e9d9ae89841df4bb0e5c1aea8b6885
c7c7389b6a06f11386435449c154c1b6878c01288eeab32e0f54ce92a5c5b7c90a978a9ce4ea61efc3d2c8617f6fa6c4
41ead48d0c0640dc03cea84b6ed19d20a545de95953270a5c20043ccd84179f46d99ee44bf4a8798a09c174ff8aac7a1
c0219509f94da75f18f1fd56aecfa7b9021de999a571a4dda2be8de2ebd439ae242fd85c8742886af570cd6f0a4c58a2
d6fe36dc75694a4459a6f54294f17ece7f4fdc09e7e8fb2b992e72a0ab92da0f00f7b73282c804815b4c674778b760bd
becb1781197c26b711796ebde491bdd2c1e8ce6fe70cdf255ff8af6badf01e977f06af4f047bb2485e5bf530e4413b32
586c6d74c886fa28de23b66a5616e7b0924c08ce87e8cce6826f3b3ef4c653d9bd103c9c8d8f9051017b7cdc4aed2507
e6480c201a46f1a537af82279a6936d0ef4b1d0e5ea60c56126c4ef38fb42bf1d881451498242173d850751c4f6b0b40
5e092141eec07faddd009722c58aa6042e404b144f1e29f76a1f0b8db7452bca3298373cb17cdf1afe0792b50500e97b
f877b834ed12f579caed92aa8fb4708ea7629aaea623c63d863b31571cbce32464bbb6f4dc62bd5a37ac860a89f3d169
e6c6d06cc146fd1b488bae21ed510b483d8e118396186623ce876b3081538731190d2a81f57cdb1a2fe86ab02ac1f804
b0693ac1b3aa3d921ed516c5c7e7162cfa17567d41dfddbf46692ab01b3b23c60e6a1778064290126fdeea97f225768d
503349510da1d0c30f6a7738f710ec4a3d38074f0baee3ea374606ac6ddb104a7ff5765cf86c189613cd19d898ecc1ef
c3b232a6769c8fb966fd9ebcccab5c9a55fdb211685e2b9136d818c3058a505e575a9d891eb61087b2e44c3a3863ffde
d8413b76bcf223d39e74c02b99fa9ef4dcfe5ef2bedd366e2f9121fd90c764a7980c2927d61f98ddb7513c2a00162738
7f5df9befb7bd6820dd4b855cd5eb1d33c128423947e7601c88a3e922b3ad444bd39fd719cda592da81626578633bcd7
b13436a9210dcfb8ac294ae29fc92f750e9087a7cd39387a84efbf6c890ecc30f44eb6f6343892de42f4368e092963a7
c6800eb141fae73be3f14e18aa303c569a303374828799d6881bfa33eb5ead1ccb3c6e0ddd04baeef518347e1b75a1c2
2f9e95add8b9cb8d394eee05b61d3795843ce031e412c9d50c429d61460812e34a5c710b8949b0cafc6396b6cbe144f2
1cb85d64987c1a89272ccba305480e2dd6ea84104578be8d7bfc817ce95fd023b69d2da01a241aa40273c7f2f1bd3862
928dd997dcb9eeb7035a5b41cfb8e6227ba4df81d12184c7117af18919a65e865c578a52870c06aca8bbc51d6b1ee68f
bff6eeb1e169f08e0aa215fcb49ac59b24a07416328d1fa64939063b9d811b47d89345f8980ee9fc514d0681b87a1a18
0869e138cb6c94f3aa4eba51c921052cbf61cc5ddae4a352b74c8ce8e8e92f6d77b6158c07a140bf8d640fc4ea05e209
dd6991b4b8945a16f372981b965cf7ca68e1d252dec7206623054e308661fae9861b7fcac3d493654d01e9dcc8d7dc21
cfa5a9251a1afd5ae0c7ec1b0526b3c0e809ec1313f531417e18fa8c3ec8bdbf9324fe8e5637fcfcf884ca05ad574e90
a3ca6bc05146bba763dd89ee448dca3868062a5f7ecd6eb4827567dac06cd468ed3a3ff218e16773767ce67954418041
ddafe8b0a311ec80c3914444208e1240568efb7493038c50c4eb4d34361ca12b2bece6d833d909761945b5b10c5ff94e
b146adb3a575922705ba342f6904c9bbb92f5a94261f47edac363f7dde7d50020cd280a308a40bc8f82d692099de6687
7424a27cc2cda56f525948c33872f91326ed5638f6169c398585a87eb519e1294f66a30331b33f35aced9d0599a83c9a
88185e1182ab98f591b235fa9f59985cc46ad443f285d9e029de0e03d7c5636881ba7123775ba908a885b132842910e1
fadca658a0a25295f5121f6087701c83cf9737f5a747945c282cecfb5ec0488d6cecc49235cd8accfeb3c2c5c76398f9
d64b25adb930fc2deb30a6e45e6999f34317a82e80eabdc489e46c4e29cab2a618fd2a45e5bb17b43ae4dc8f851d17af
047217194a01a40a045d1c74a06328d3ec001730a0fde471367db054dcbac53f683f3f522308f40f7dd3a6a467093897
1b5cb6cecce1bdf9ea0c68fb90a4ace3991f8fa6c19dbf9792dbab79faab39e0b0663730de3396c6bb3d40e386880c72
6361f675be68f096e54cd833f4e06b50f0388370bdf65fa4c4db0d4448ff89b48b694246bf3da3c9d9c8e7b24289281d
557e1657574aa4d54cc39981bfc31f97b37edb14ec7f197d161bd0409a99bb1867a54b2c5dca27db5ed29eeb907114cf
f141467f8e7ae6a012a746547c318551f8eb6090882baed7834ee8e0daa48878e822d8afdbe7b525d5b90d8152c59eba
744e97057789f5431586ca9e5e42c0d9bf2d5810e145c64c054e58211cdf6afcb21b56b1f778f33d3c731df01aeba4a7
b27c148ef046e856aa895ba02b9f8f982d42e3e5776c4b8f0c0e738c2e201efe2f70645286faae60a822663746233ba4
b53ce532c98b059a24c890d3d12492cfc7fb92172b9dda4f31d296185f34ec5dedc35714a5c73d117cedd037a1f4ef3c
'''
# print(len(sus.strip().splitlines()))