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
exports.makeSnarkJsZKOperator = exports.makeLocalSnarkJsZkOperator = void 0;
// 5 pages is enough for the witness data
// calculation
const WITNESS_MEMORY_SIZE_PAGES = 5;
/**
 * Make a ZK operator from the snarkjs dependency
 * @param logger
 * @returns
 */
async function makeLocalSnarkJsZkOperator(type) {
    const { join } = await Promise.resolve().then(() => __importStar(require('path')));
    const folder = `../resources/${type}`;
    return makeSnarkJsZKOperator({
        getZkey: () => ({
            data: join(__dirname, `${folder}/circuit_final.zkey`)
        }),
        getCircuitWasm: () => join(__dirname, `${folder}/circuit.wasm`),
    });
}
exports.makeLocalSnarkJsZkOperator = makeLocalSnarkJsZkOperator;
/**
 * Make a SnarkJS ZK operator from the provided
 * fns to get the circuit wasm and zkey
 */
function makeSnarkJsZKOperator({ getCircuitWasm, getZkey }) {
    // require here to avoid loading snarkjs in
    // any unsupported environments
    const snarkjs = require('snarkjs');
    let zkey;
    let circuitWasm;
    let wc;
    return {
        async generateWitness(input, logger) {
            circuitWasm || (circuitWasm = getCircuitWasm());
            wc || (wc = (async () => {
                if (!snarkjs.wtns.getWtnsCalculator) {
                    return;
                }
                // hack to allocate a specific memory size
                // because the Memory size isn't configurable
                // in the circom_runtime package
                const CurMemory = WebAssembly.Memory;
                WebAssembly.Memory = class extends WebAssembly.Memory {
                    constructor() {
                        super({ initial: WITNESS_MEMORY_SIZE_PAGES });
                    }
                };
                try {
                    const rslt = await snarkjs.wtns.getWtnsCalculator(await circuitWasm, logger);
                    return rslt;
                }
                finally {
                    WebAssembly.Memory = CurMemory;
                }
            })());
            const wtns = { type: 'mem' };
            if (await wc) {
                await snarkjs.wtns.wtnsCalculateWithCalculator(input, await wc, wtns);
            }
            else {
                await snarkjs.wtns.calculate(input, await circuitWasm, wtns);
            }
            return wtns.data;
        },
        async groth16Prove(witness, logger) {
            zkey || (zkey = getZkey());
            return snarkjs.groth16.prove((await zkey).data, witness, logger);
        },
        async groth16Verify(publicSignals, proof, logger) {
            zkey || (zkey = getZkey());
            const zkeyResult = await zkey;
            if (!zkeyResult.json) {
                zkeyResult.json = await snarkjs.zKey
                    .exportVerificationKey(zkeyResult.data);
            }
            return snarkjs.groth16.verify(zkeyResult.json, publicSignals, proof, logger);
        },
        release() {
            zkey = undefined;
            circuitWasm = undefined;
            wc = undefined;
        }
    };
}
exports.makeSnarkJsZKOperator = makeSnarkJsZKOperator;
