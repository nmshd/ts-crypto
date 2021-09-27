import { CoreBuffer, Encoding, ICoreBuffer } from "../CoreBuffer";
import { SodiumWrapper } from "../SodiumWrapper";

/**
 * The hash algorithm to use
 */
export const enum CryptoHashAlgorithm {
    /** SHA256 Hash Algorithm with a hash of 32 bytes */
    SHA256 = 1,
    /** SHA512 Hash Algorithm with a hash of 64 bytes */
    SHA512 = 2,

    BLAKE2B = 3
}

export interface ICryptoHash {}

export interface ICryptoHashStatic {
    new (): ICryptoHash;
    verify(content: ICoreBuffer, hash: ICoreBuffer, algorithm: CryptoHashAlgorithm): Promise<boolean>;
    hash(content: ICoreBuffer, algorithm: CryptoHashAlgorithm): Promise<CoreBuffer>;
    sha256(content: string, hash?: string): Promise<string | boolean>;
    sha512(content: string, hash?: string): Promise<string | boolean>;
}

export class CryptoHash implements ICryptoHash {
    /**
     * Hashes the given content with the specified algorithm and compares it to the given hash. Returns
     * a Promise object of the match (which can be true or false).
     *
     * @param content The IBuffer object to be hashed and verified (IS)
     * @param hash The IBuffer object of an already existing hash which acts as the verification (SHOULD BE)
     * @param algorithm The [[CryptoHashAlgorithm]] to be used as the hash algorithm
     * @returns A Promise object, resolved by true if the content matches to the hash, false otherwise
     */
    public static async verify(
        content: ICoreBuffer,
        hash: ICoreBuffer,
        algorithm: CryptoHashAlgorithm
    ): Promise<boolean> {
        const hashBuffer = await this.hash(content, algorithm);
        const buffer: ICoreBuffer = new CoreBuffer(hashBuffer);

        if (buffer.equals(hash)) {
            return true;
        }
        return false;
    }

    /**
     * Hashes the given content with the specified algorithm and returns the hash as a [[Buffer]] object.
     *
     * @param content The IBuffer object to be hashed and verified (IS)
     * @param algorithm The [[CryptoHashAlgorithm]] to be used as the hash algorithm
     * @returns A Promise object, resolving to true if the content matches to the hash, false otherwise
     */
    public static async hash(content: ICoreBuffer, algorithm: CryptoHashAlgorithm): Promise<CoreBuffer> {
        let hashBuffer: Uint8Array;
        const sodium = await SodiumWrapper.ready();
        switch (algorithm) {
            case CryptoHashAlgorithm.SHA256:
                hashBuffer = sodium.crypto_hash_sha256(content.buffer);
                break;
            case CryptoHashAlgorithm.SHA512:
                hashBuffer = sodium.crypto_hash_sha512(content.buffer);
                break;
            default:
                throw new Error("This hash algorithm is not supported.");
        }

        return new CoreBuffer(hashBuffer);
    }

    /**
     * Helper function which either creates an SHA-256 hash of the given content and returns it
     * as a hex string (when leaving the hash parameter unset) or verifies an already existing
     * SHA-256 hash when the hash parameter is set. Please be advised that the helper functions
     * use utf-8 encoded strings as input encoding and hex as output encoding, rather than the
     * IBuffer objects used in the [[hash]] and [[verify]] methods.
     *
     * @param content The content as string which should should be hashed (IS)
     * @param hash The optional SHA-256 hash of the content (SHOULD BE)
     * @returns A Promise object, either resolving to the SHA-256 hash of the given string (if the
     * hash parameter is omitted. If the hash parameter is given, the Promise is resolving to either
     * true or false, depending if the hashes match or not).
     */
    public static async sha256(content: string, hash?: string): Promise<string | boolean> {
        const bufferContent = CoreBuffer.fromString(content, Encoding.Utf8);
        if (hash) {
            const bufferHash = CoreBuffer.fromString(hash, Encoding.Hex);
            return await this.verify(bufferContent, bufferHash, CryptoHashAlgorithm.SHA256);
        }
        const created = await this.hash(bufferContent, CryptoHashAlgorithm.SHA256);
        return created.toString(Encoding.Hex);
    }

    /**
     * Helper function which either creates an SHA-512 hash of the given content and returns it
     * as a hex string (when leaving the hash parameter unset) or verifies an already existing
     * SHA-512 hash when the hash parameter is set. Please be advised that the helper functions
     * use utf-8 encoded strings as input encoding and hex as output encoding, rather than the
     * IBuffer objects used in the [[hash]] and [[verify]] methods.
     *
     * @param content The content as string which should should be hashed (IS)
     * @param hash The optional SHA-512 hash of the content (SHOULD BE)
     * @returns A Promise object, either resolving to the SHA-512 hash of the given string (if the
     * hash parameter is omitted. If the hash parameter is given, the Promise is resolving to either
     * true or false, depending if the hashes match or not).
     */
    public static async sha512(content: string, hash?: string): Promise<string | boolean> {
        const bufferContent = CoreBuffer.fromString(content, Encoding.Utf8);
        if (hash) {
            const bufferHash = CoreBuffer.fromString(hash, Encoding.Hex);
            return await this.verify(bufferContent, bufferHash, CryptoHashAlgorithm.SHA512);
        }
        const created = await this.hash(bufferContent, CryptoHashAlgorithm.SHA512);
        return created.toString(Encoding.Hex);
    }
}
