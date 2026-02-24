// vim: ts=4:sw=4

'use strict';

const nodeCrypto = require('crypto');
const assert = require('assert');


function assertBuffer(value) {
    if (!Buffer.isBuffer(value)) {
        const name = value == null ? String(value) : value.constructor.name;
        throw TypeError(`Expected Buffer instead of: ${name}`);
    }
    return value;
}


function encrypt(key, data, iv) {
    assertBuffer(key);
    assertBuffer(data);
    assertBuffer(iv);
    const cipher = nodeCrypto.createCipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([cipher.update(data), cipher.final()]);
}


function decrypt(key, data, iv) {
    assertBuffer(key);
    assertBuffer(data);
    assertBuffer(iv);
    const decipher = nodeCrypto.createDecipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([decipher.update(data), decipher.final()]);
}


function calculateMAC(key, data) {
    assertBuffer(key);
    assertBuffer(data);
    const hmac = nodeCrypto.createHmac('sha256', key);
    hmac.update(data);
    return Buffer.from(hmac.digest());
}


function hash(data) {
    assertBuffer(data);
    const sha512 = nodeCrypto.createHash('sha512');
    sha512.update(data);
    return sha512.digest();
}


// Salts always end up being 32 bytes
function deriveSecrets(input, salt, info, chunks) {
    // Specific implementation of RFC 5869 that only returns the first 3 32-byte chunks
    assertBuffer(input);
    assertBuffer(salt);
    assertBuffer(info);
    if (salt.byteLength != 32) {
        throw new Error("Got salt of incorrect length");
    }
    chunks = chunks || 3;
    assert(chunks >= 1 && chunks <= 3);
    const PRK = calculateMAC(salt, input);
    const infoOffset = 32;
    const infoArray = Buffer.allocUnsafe(info.byteLength + 1 + infoOffset);
    infoArray.fill(0, 0, infoOffset);
    info.copy(infoArray, infoOffset);
    infoArray[infoArray.length - 1] = 1;
    const signed = [calculateMAC(PRK, infoArray.slice(infoOffset))];
    if (chunks > 1) {
        infoArray.set(signed[signed.length - 1]);
        infoArray[infoArray.length - 1] = 2;
        signed.push(calculateMAC(PRK, infoArray));
    }
    if (chunks > 2) {
        infoArray.set(signed[signed.length - 1]);
        infoArray[infoArray.length - 1] = 3;
        signed.push(calculateMAC(PRK, infoArray));
    }
    return signed;
}

function verifyMAC(data, key, mac, length) {
    assertBuffer(data);
    assertBuffer(key);
    assertBuffer(mac);
    const calculatedMac = calculateMAC(key, data).slice(0, length);
    if (mac.length !== length || calculatedMac.length !== length) {
        throw new Error("Bad MAC length");
    }
    if (!nodeCrypto.timingSafeEqual(mac, calculatedMac)) {
        throw new Error("Bad MAC");
    }
}

module.exports = {
    deriveSecrets,
    decrypt,
    encrypt,
    hash,
    calculateMAC,
    verifyMAC
};
