"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.makeLocalGnarkZkOperator = void 0;
const path_1 = require("path");
let koffi = require('koffi');
let verify;
let init;
let free;
let initComplete;
let prove;
try {
    if (koffi === null || koffi === void 0 ? void 0 : koffi.version) {
        koffi.reset(); //otherwise tests will fail
        // define object GoSlice to map to:
        // C type struct { void *data; GoInt len; GoInt cap; }
        const GoSlice = koffi.struct('GoSlice', {
            data: 'void *',
            len: 'longlong',
            cap: 'longlong'
        });
        const ProveReturn = koffi.struct('ProveReturn', {
            r0: 'void *',
            r1: 'longlong',
        });
        const resFolder = `../resources/gnark`;
        const arch = process.arch;
        const libVerifyPath = (0, path_1.join)(__dirname, `${resFolder}/${arch}/libverify.so`);
        const libProvePath = (0, path_1.join)(__dirname, `${resFolder}/${arch}/libprove.so`);
        const libVerify = koffi.load(libVerifyPath);
        const libProve = koffi.load(libProvePath);
        verify = libVerify.func('Verify', 'unsigned char', [GoSlice]);
        init = libProve.func('Init', 'void', []);
        free = libProve.func('Free', 'void', ['void *']);
        initComplete = libProve.func('InitComplete', 'unsigned char', []);
        prove = libProve.func('Prove', ProveReturn, [GoSlice]);
    }
}
catch (e) {
    koffi = undefined;
    console.log("Gnark is only supported on linux x64 & ARM64.", e.toString());
}
async function makeLocalGnarkZkOperator(cipher) {
    if (koffi) {
        return Promise.resolve({
            async generateWitness(input) {
                return generateGnarkWitness(cipher, input);
            },
            //used in nodeJS only for tests
            async groth16Prove(witness) {
                const wtns = {
                    data: Buffer.from(witness),
                    len: witness.length,
                    cap: witness.length
                };
                const res = prove(wtns);
                const resJson = Buffer.from(koffi.decode(res.r0, 'unsigned char', res.r1)).toString();
                free(res.r0); // Avoid memory leak!
                return Promise.resolve(JSON.parse(resJson));
            },
            async groth16Verify(publicSignals, proof) {
                const proofStr = proof['proofJson'];
                const verifyParams = {
                    cipher: cipher,
                    proof: proofStr,
                    publicSignals: publicSignals,
                };
                const paramsJson = JSON.stringify(verifyParams);
                const paramsBuf = strToUint8Array(paramsJson);
                const params = {
                    data: paramsBuf,
                    len: paramsJson.length,
                    cap: paramsJson.length
                };
                return verify(params) === 1;
            },
        });
    }
    else {
        return Promise.resolve({
            async generateWitness(input) {
                return generateGnarkWitness(cipher, input);
            },
            async groth16Prove(witness) {
                throw new Error("not supported");
            },
            async groth16Verify(publicSignals, proof) {
                throw new Error("not supported");
            },
        });
    }
}
exports.makeLocalGnarkZkOperator = makeLocalGnarkZkOperator;
function generateGnarkWitness(cipher, input) {
    //input is already in bits, sometimes groups of bits
    const proofParams = {
        cipher: cipher,
        key: input.key,
        nonce: input.nonce,
        counter: input.counter,
        input: input.in,
    };
    const paramsJson = JSON.stringify(proofParams);
    return strToUint8Array(paramsJson);
}
function strToUint8Array(str) {
    return new TextEncoder().encode(str);
}
