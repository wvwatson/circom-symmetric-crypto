"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CONFIG = void 0;
const utils_1 = require("./utils");
exports.CONFIG = {
    'chacha20': {
        chunkSize: 16,
        bitsPerWord: 32,
        keySizeBytes: 32,
        ivSizeBytes: 12,
        startCounter: 1,
        // num of blocks per chunk
        blocksPerChunk: 1,
        // chacha20 circuit uses LE encoding
        isLittleEndian: true,
        uint8ArrayToBits: (arr) => ((0, utils_1.uintArrayToBits)((0, utils_1.toUintArray)(arr))),
        bitsToUint8Array: (bits) => {
            const arr = (0, utils_1.bitsToUintArray)(bits);
            return (0, utils_1.toUint8Array)(arr);
        },
    },
    'aes-256-ctr': {
        chunkSize: 64,
        bitsPerWord: 8,
        keySizeBytes: 32,
        ivSizeBytes: 12,
        startCounter: 2,
        // num of blocks per chunk
        blocksPerChunk: 4,
        // AES circuit uses BE encoding
        isLittleEndian: false,
        uint8ArrayToBits: utils_1.uint8ArrayToBits,
        bitsToUint8Array: utils_1.bitsToUint8Array,
    },
    'aes-128-ctr': {
        chunkSize: 64,
        bitsPerWord: 8,
        keySizeBytes: 16,
        ivSizeBytes: 12,
        startCounter: 2,
        // num of blocks per chunk
        blocksPerChunk: 4,
        // AES circuit uses BE encoding
        isLittleEndian: false,
        uint8ArrayToBits: utils_1.uint8ArrayToBits,
        bitsToUint8Array: utils_1.bitsToUint8Array,
    }
};
