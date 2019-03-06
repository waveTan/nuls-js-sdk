const nuls = require("./lib/sdk");
require("./lib/txs")


console.log("测试eckey生成：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：")
var params = nuls.newEcKey();
console.log('pri:' + params.pri)
console.log('pub:' + params.pub)

var pri = "79d6f23d99b1b7e2a97579dfef7d8ab627ee18cd545a266c0c7c5f9e5e04f355";
var pub = "025feaac22fd90ab25a6eba62aec98fd3bec04201bde81d53bbbe597b149097d16";

console.log("resuslt:" + (pub == nuls.getPub(pri)))
console.log("测试address生成：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：")

var address = nuls.getStringAddress(null, pub);
console.log(address)
var address1 = nuls.getStringAddress(pri, null);
console.log("resuslt:" + (address == address1))

console.log("测试加密解密：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：")

var encryptedValue = nuls.encrypteByAES(pri, "12312312");
console.log(encryptedValue)

var value = nuls.decrypteOfAES(encryptedValue, "12312312")
console.log('result:' + (value == pri))

console.log("测试数据签名：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：")
var dataHex = "9e9644d3be6c9f90947580ad74641e24f4d0f791c6182c06ec76e270f703feb8";
var sign = nuls.signature(dataHex, pri);
console.log(sign)
var result = nuls.verifySign(dataHex, sign, pub)
console.log("resuslt:" + result)
console.log("测试HASH计算：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：")

var dataHex = "3044022027218a6b986c55cf800a6fbb9c00001e80d47e47e6e5f13eec48ee825c9b1d6d02205fc7900a38c455e325fe90531604fd0095f36da45f2740356533b4714830fbc6";
var hash256 = nuls.getSha256Hex(dataHex);
console.log(hash256)
console.log("resuslt:" + (hash256 == 'b35baba31a11618b38023cee0a199598819da9d62d6bbb1faf36b0034c48c29d'))

console.log("交易测试：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：：")
var tx = new TransferTransaction();
tx.remark = 'for test';
tx.time = 123456789
tx.inputs = [{owner: '9e9644d3be6c9f90947580ad74641e24f4d0f791c6182c06ec76e270f703feb801', na: 100000000, lockTime: 0}]
tx.outputs = [{owner: "Nse2ACrBkXJiq5KoFCJCb5NaJT9bk4nZ", na: 99000000, lockTime: 0}];
//计算hash
var hash = nuls.getTxHash(tx);
console.log(hash.toString('hex'))
//签名
nuls.signatureTx(tx, pub, pri);

var bytes = tx.txSerialize()
console.log(bytes.toString('hex'))
console.log('020015cd5b07000008666f722074657374ffffffff01219e9644d3be6c9f90947580ad74641e24f4d0f791c6182c06ec76e270f703feb80100e1f50500000000000000000000011704230182bdc042f1ab2ee51d31d6c7038c31bc52a791c7c09ee605000000000000000000006b21025feaac22fd90ab25a6eba62aec98fd3bec04201bde81d53bbbe597b149097d1600473045022100e80872166382f59f60b57fdc830617bfac70c849e5cbe2634816ecad73cfe54502205978614849822d02a3e72cb26b189da4779f6bb61e565102b8543deed956e08a')
console.log("创建交易并签名完成")