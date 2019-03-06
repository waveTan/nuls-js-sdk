const bitcore = require('bitcore-lib')
//将数字转为6个字节的字节数组
function toUInt48LE(value) {
    // var writer = new bitcore.encoding.BufferWriter();
    // writer.writeUInt64LEBN(value);
    // return writer.toBuffer().subarray(2);
    var buf = Buffer.alloc(6);
    buf.writeUIntLE(value, 0, 6);
    return buf;

}

Serializer = function (bufWriter) {
    if (!bufWriter) {
        bufWriter = new bitcore.encoding.BufferWriter();
    }
    this.writeUINT48LE = function (value) {
        bufWriter.write(toUInt48LE(value));
    }
    this.writeString = function (value) {
        if (!value || value.length == 0) {
            bufWriter.write(Buffer.from([0x00]));
            return;
        }
        var buf = Buffer.from(value, "UTF-8");
        bufWriter.writeVarintNum(buf.length);
        bufWriter.write(buf);
    }
    this.writeBytesWithLength = function (value) {
        if (!value || value.length == 0) {
            bufWriter.write(Buffer.from([0x00]));
            return;
        }
        bufWriter.writeVarintNum(value.length);
        bufWriter.write(value);
    }

    this.writeBoolean = function (value) {
        if (value) {
            bufWriter.write(1);
        } else {
            bufWriter.write(0);
        }
    }

    this.getBufWriter = function () {
        return bufWriter;
    }

    this.writeUInt64LE = function (value) {
        bufWriter.writeUInt64LEBN(new bitcore.crypto.BN(value));
    }
}