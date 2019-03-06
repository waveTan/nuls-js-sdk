const randomBytes = require('randombytes')
const BigInteger = require('bigi')
const ecurve = require('ecurve')
const CryptoJS = require('crypto-js')
const sha256 = require('sha256')
const rs = require('jsrsasign')
var bs58 = require('bs58')
const cryptos = require("crypto")
const bitcore = require("bitcore-lib")
const iv = CryptoJS.enc.Hex.parse('0000000000000000');

module.exports = {
    //生成公私钥对
    newEcKey: function () {
        var keys = {};
        var randombytes = randomBytes(32)
        randombytes[0] = randombytes[0] >> 1
        var privateKey = Buffer.from(randombytes, 'hex').toString('hex')
        keys['pri'] = privateKey
        keys['pub'] = this.getPub(privateKey);
        return keys;
    }
    ,
    //获取公钥
    getPub: function (randombytes) {
        var privateKey = Buffer.from(randombytes, 'hex');
        var ecparams = ecurve.getCurveByName('secp256k1')
        var curvePt = ecparams.G.multiply(BigInteger.fromBuffer(privateKey))
        var publicKey = curvePt.getEncoded(true)
        return publicKey.toString('hex');
    },
    //根据公钥或者私钥获取地址字符串
    getStringAddress: function (pri, pub) {
        if (!pub) {
            pub = this.getPub(pri)
        }
        var pubBuffer = Buffer.from(pub, 'hex');
        var sha = cryptos.createHash('sha256').update(pubBuffer).digest()
        var pubkeyHash = cryptos.createHash('rmd160').update(sha).digest()
        var addrBuffer = Buffer.concat([Buffer.from([0xFF & 8964 >> 0]), Buffer.from([0xFF & 8964 >> 8]), Buffer.from([1]), pubkeyHash]);
        var xor = 0x00
        var temp = "";
        var tempBuffer = Buffer.allocUnsafe(addrBuffer.length + 1);
        for (var i = 0; i < addrBuffer.length; i++) {
            temp = addrBuffer[i];
            temp = temp > 127 ? temp - 256 : temp;
            tempBuffer[i] = temp
            xor ^= temp
        }
        tempBuffer[addrBuffer.length] = xor
        return bs58.encode(tempBuffer)
    },
    //aes 加密
    encrypteByAES: function (value, password) {
        let key = CryptoJS.enc.Hex.parse(sha256(password));
        let srcs = CryptoJS.enc.Hex.parse(value);
        let encrypted = CryptoJS.AES.encrypt(srcs, key, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });
        return encrypted.ciphertext.toString().toLowerCase();
    },
    decrypteOfAES: function (encryptedValue, password) {
        let key = CryptoJS.enc.Hex.parse(sha256(password));
        let encryptedHexStr = CryptoJS.enc.Hex.parse(encryptedValue);
        let srcs = CryptoJS.enc.Base64.stringify(encryptedHexStr);
        let decrypt = CryptoJS.AES.decrypt(srcs, key, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });
        return decrypt.toString().toLowerCase();
    },
    signature: function (dataHex, priHex) {
        var ec = new rs.KJUR.crypto.ECDSA({'curve': 'secp256k1'});
        var signValue = ec.signHex(dataHex, priHex);
        return signValue;
    },
    signatureTx: function (tx, pubHex, priHex) {

        var pub = Buffer.from(pubHex, 'hex');
        var signValue = Buffer.from(this.signature(tx.hash.subarray(1).toString('hex'), priHex), 'hex');
        // var sig = Buffer.concat([pub, Buffer.from([0x00], signValue)], pub.length + 1 + signValue.length);
        tx.p2PHKSignatures = [{'pub': pub, signValue: signValue}];
    },
    verifySign: function (dataHex, signHex, pubHex) {
        //todo 有问题，不能正确验证
        var ec = new rs.KJUR.crypto.ECDSA({'curve': 'secp256k1'});
        return ec.verifyHex(dataHex, signHex, pubHex);
    },
    getSha256Hex: function (seriHex) {
        let sha256 = cryptos.createHash('SHA256');
        let data = Buffer.from(seriHex, 'hex');
        sha256.update(data);
        return sha256.digest('hex');
    },
    getSha256TiwceBuf: function (buf) {
        return bitcore.crypto.Hash.sha256sha256(buf);
    },
    getTxHash: function (transaction) {
        var bytes = transaction.serializeForHash();
        var hash = this.getSha256TiwceBuf(bytes);

        transaction.hash = Buffer.concat([Buffer.from([0x00]), hash], hash.length + 1);
        return transaction.hash;
    }

}