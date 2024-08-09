"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyProof = exports.generateProof = void 0;
const snarkjs = __importStar(require("snarkjs"));
const utils_1 = require("../utils");
const CIRCUIT_WASM_PATH = "./resources/aes/circuit.wasm";
async function generateProof({ key, iv, }, { ciphertext,
//redactedPlaintext,
 }, zkey) {
    //convert to bit arrays
    const encKey = buffer2bits(Buffer.from(key));
    const ivCounter = buffer2bits(Buffer.from(iv));
    const ct = buffer2bits(Buffer.from(ciphertext));
    const { proof, publicSignals } = await snarkjs.groth16.fullProve({
        encKey: encKey,
        iv: ivCounter,
        ciphertext: ct,
    }, CIRCUIT_WASM_PATH, zkey.data);
    return {
        proofJson: JSON.stringify(proof),
        plaintext: (0, utils_1.bitsToUint8Array)(publicSignals
            .slice(0, ct.length * 8))
    };
}
exports.generateProof = generateProof;
async function verifyProof({ proofJson }, publicInput, zkey) {
    if (!zkey.json) {
        zkey.json = await snarkjs.zKey.exportVerificationKey(zkey.data);
    }
    const pubInputs = getSerialisedPublicInputs(publicInput);
    return await snarkjs.groth16.verify(zkey.json, pubInputs, JSON.parse(proofJson));
}
exports.verifyProof = verifyProof;
/**
 * Serialise public inputs to array of numbers for the ZK circuit
 * the format is spread (output, ciphertext, redactedPlaintext)
 * @param inp
 */
function getSerialisedPublicInputs(inp) {
    return [
        ...Array.from(buffer2bits(Buffer.from(inp.ciphertext))),
    ];
}
function buffer2bits(buff) {
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
