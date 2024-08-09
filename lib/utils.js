"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getCounterForChunk = exports.getFullCounterIv = exports.bitsToUintArray = exports.uintArrayToBits = exports.bitsToUint8Array = exports.uint8ArrayToBits = exports.padArray = exports.makeUint8Array = exports.padU8ToU32Array = exports.toUint8Array = exports.makeUintArray = exports.toUintArray = exports.REDACTION_CHAR_CODE = exports.BITS_PER_WORD = void 0;
const config_1 = require("./config");
exports.BITS_PER_WORD = 32;
// we use this to pad the ciphertext
exports.REDACTION_CHAR_CODE = '*'.charCodeAt(0);
function toUintArray(buf) {
    const arr = makeUintArray(buf.length / 4);
    const arrView = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    for (let i = 0; i < arr.length; i++) {
        arr[i] = arrView.getUint32(i * 4, true);
    }
    return arr;
}
exports.toUintArray = toUintArray;
function makeUintArray(init) {
    return typeof init === 'number'
        ? new Uint32Array(init)
        : Uint32Array.from(init);
}
exports.makeUintArray = makeUintArray;
/**
 * Convert a UintArray (uint32array) to a Uint8Array
 */
function toUint8Array(buf) {
    const arr = new Uint8Array(buf.length * 4);
    const arrView = new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
    for (let i = 0; i < buf.length; i++) {
        arrView.setUint32(i * 4, buf[i], true);
    }
    return arr;
}
exports.toUint8Array = toUint8Array;
function padU8ToU32Array(buf) {
    if (buf.length % 4 === 0) {
        return buf;
    }
    return makeUint8Array([
        ...Array.from(buf),
        ...new Array(4 - buf.length % 4).fill(exports.REDACTION_CHAR_CODE)
    ]);
}
exports.padU8ToU32Array = padU8ToU32Array;
function makeUint8Array(init) {
    return typeof init === 'number'
        ? new Uint8Array(init)
        : Uint8Array.from(init);
}
exports.makeUint8Array = makeUint8Array;
function padArray(buf, size) {
    return makeUintArray([
        ...Array.from(buf),
        ...new Array(size - buf.length).fill(exports.REDACTION_CHAR_CODE)
    ]);
}
exports.padArray = padArray;
/**
 * Converts a Uint8Array to an array of bits.
 * BE order.
 */
function uint8ArrayToBits(buff) {
    const res = [];
    for (let i = 0; i < buff.length; i++) {
        for (let j = 0; j < 8; j++) {
            if ((buff[i] >> 7 - j) & 1) {
                res.push(1);
            }
            else {
                res.push(0);
            }
        }
    }
    return res;
}
exports.uint8ArrayToBits = uint8ArrayToBits;
/**
 * Converts an array of bits to a Uint8Array.
 * Expecting BE order.
 * @param bits
 * @returns
 */
function bitsToUint8Array(bits) {
    const arr = new Uint8Array(bits.length / 8);
    for (let i = 0; i < bits.length; i += 8) {
        const uint = bitsToNum(bits.slice(i, i + 8));
        arr[i / 8] = uint;
    }
    return arr;
}
exports.bitsToUint8Array = bitsToUint8Array;
/**
 * Converts a Uint32Array to an array of bits.
 * LE order.
 */
function uintArrayToBits(uintArray) {
    const bits = [];
    for (let i = 0; i < uintArray.length; i++) {
        const uint = uintArray[i];
        bits.push(numToBitsNumerical(uint));
    }
    return bits;
}
exports.uintArrayToBits = uintArrayToBits;
function bitsToUintArray(bits) {
    const uintArray = new Uint32Array(bits.length / exports.BITS_PER_WORD);
    for (let i = 0; i < bits.length; i += exports.BITS_PER_WORD) {
        const uint = bitsToNum(bits.slice(i, i + exports.BITS_PER_WORD));
        uintArray[i / exports.BITS_PER_WORD] = uint;
    }
    return uintArray;
}
exports.bitsToUintArray = bitsToUintArray;
function numToBitsNumerical(num, bitCount = exports.BITS_PER_WORD) {
    const bits = [];
    for (let i = 2 ** (bitCount - 1); i >= 1; i /= 2) {
        const bit = num >= i ? 1 : 0;
        bits.push(bit);
        num -= bit * i;
    }
    return bits;
}
function bitsToNum(bits) {
    let num = 0;
    let exp = 2 ** (bits.length - 1);
    for (let i = 0; i < bits.length; i++) {
        num += bits[i] * exp;
        exp /= 2;
    }
    return num;
}
/**
 * Combines a 12 byte nonce with a 4 byte counter
 * to make a 16 byte IV.
 */
function getFullCounterIv(nonce, counter) {
    const iv = Buffer.alloc(16);
    iv.set(nonce, 0);
    iv.writeUInt32BE(counter, 12);
    return iv;
}
exports.getFullCounterIv = getFullCounterIv;
/**
 * Get the counter to use for a given chunk.
 * @param algorithm
 * @param offsetInChunks
 * @returns
 */
function getCounterForChunk(algorithm, offsetInChunks) {
    const { startCounter, blocksPerChunk } = config_1.CONFIG[algorithm];
    return startCounter + offsetInChunks * blocksPerChunk;
}
exports.getCounterForChunk = getCounterForChunk;
