import { GenerateProofOpts, Proof, VerifyProofOpts } from "./types";
/**
 * Generate ZK proof for CHACHA20-CTR encryption.
 * Circuit proves that the ciphertext is a
 * valid encryption of the given plaintext.
 * The plaintext can be partially redacted.
 */
export declare function generateProof(opts: GenerateProofOpts): Promise<Proof>;
/**
 * Generate a ZK witness for the symmetric encryption circuit.
 * This witness can then be used to generate a ZK proof,
 * using the operator's groth16Prove function.
 */
export declare function generateZkWitness({ algorithm, privateInput: { key, iv, offset, }, publicInput: { ciphertext }, operator }: GenerateProofOpts): Promise<Uint8Array>;
/**
 * Verify a ZK proof for CHACHA20-CTR encryption.
 *
 * @param proofs JSON proof generated by "generateProof"
 * @param publicInput
 * @param zkey
 */
export declare function verifyProof({ proof: { algorithm, plaintext, proofJson }, publicInput: { ciphertext }, operator, logger }: VerifyProofOpts): Promise<void>;
