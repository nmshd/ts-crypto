import { CoreBuffer, Encoding, ICoreBuffer } from "../CoreBuffer";
import { getProvider, ProviderIdentifier } from "../crypto-layer/CryptoLayerProviders";
import { CryptoHashWithCryptoLayer } from "../crypto-layer/hash/CryptoHash";
import { SodiumWrapper } from "../SodiumWrapper";

/**
 * The hash algorithm to use
 */
export const enum CryptoHashAlgorithm {
    /** SHA256 Hash Algorithm with a hash of 32 bytes */
    SHA256 = 1,
    /** SHA512 Hash Algorithm with a hash of 64 bytes */
    SHA512 = 2,

    // Present in the original enum, but fallback was not implemented for it
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

/**
 * The original libsodium-based implementation of hashing (fallback).
 *
 * Renamed to avoid confusion with the new default, but the code is identical
 * to your original CryptoHash class aside from this name change.
 */
export class CryptoHashWithLibsodium {
    /**
     * Hashes the given content with the specified algorithm and compares it to the given hash. Returns
     * a Promise object of the match (which can be true or false).
     *
     * @param content The IBuffer object to be hashed and verified (IS)
     * @param hash The IBuffer object of an already existing hash which acts as the verification (SHOULD BE)
     * @param algorithm The [[CryptoHashAlgorithm]] to be used as the hash algorithm
     * @returns A Promise object, resolved by true if the content matches the hash, false otherwise
     */
    public static async verify(
        content: ICoreBuffer,
        hash: ICoreBuffer,
        algorithm: CryptoHashAlgorithm
    ): Promise<boolean> {
        const generatedHash = await this.hash(content, algorithm);
        return generatedHash.equals(hash);
    }

    /**
     * Hashes the given content with the specified algorithm and returns the hash as a [[CoreBuffer]] object.
     *
     * @param content The IBuffer object to be hashed
     * @param algorithm The [[CryptoHashAlgorithm]] to be used as the hash algorithm
     * @returns A Promise resolving to the hash as a [[CoreBuffer]] object
     */
    public static async hash(content: ICoreBuffer, algorithm: CryptoHashAlgorithm): Promise<CoreBuffer> {
        const sodium = await SodiumWrapper.ready();
        let hashBuffer: Uint8Array;

        switch (algorithm) {
            case CryptoHashAlgorithm.SHA256:
                hashBuffer = sodium.crypto_hash_sha256(content.buffer);
                break;
            case CryptoHashAlgorithm.SHA512:
                hashBuffer = sodium.crypto_hash_sha512(content.buffer);
                break;
            default:
                // Exactly as in the original code
                throw new Error("This hash algorithm is not supported.");
        }

        return new CoreBuffer(hashBuffer);
    }

    /**
     * Helper function which either creates an SHA-256 hash of the given content and returns it
     * as a hex string (when leaving the hash parameter unset) or verifies an already existing
     * SHA-256 hash when the hash parameter is set. Please be advised that the helper functions
     * use UTF-8 encoded strings as input encoding and hex as output encoding, rather than the
     * [[CoreBuffer]] objects used in the [[hash]] and [[verify]] methods.
     *
     * @param content The content as string which should be hashed (IS)
     * @param hash The optional SHA-256 hash of the content (SHOULD BE)
     * @returns A Promise object, either resolving to the SHA-256 hash of the given string (if the
     * hash parameter is omitted) or true/false depending if the hashes match (if the hash parameter is specified).
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
     * use UTF-8 encoded strings as input encoding and hex as output encoding, rather than the
     * [[CoreBuffer]] objects used in the [[hash]] and [[verify]] methods.
     *
     * @param content The content as string which should be hashed (IS)
     * @param hash The optional SHA-512 hash of the content (SHOULD BE)
     * @returns A Promise object, either resolving to the SHA-512 hash of the given string (if the
     * hash parameter is omitted) or true/false depending if the hashes match (if the hash parameter is specified).
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

/**
 * Indicates whether a crypto-layer provider has been initialized.
 */
let providerInitialized = false;

/**
 * Initializes the hashing functionality with the specified crypto-layer provider.
 *
 * If the given provider is successfully retrieved, `providerInitialized` will be set to true,
 * causing subsequent hash operations to use the Rust-based crypto layer by default.
 * Otherwise, libsodium will be used as a fallback.
 *
 * @param providerIdent - The identifier of the crypto-layer provider to initialize.
 */
export function initCryptoHash(providerIdent: ProviderIdentifier): void {
    if (getProvider(providerIdent)) {
        providerInitialized = true;
    }
}

/**
 * The new CryptoHash class that uses the Rust-based crypto-layer by default (if initialized),
 * and falls back to [[CryptoHashWithLibsodium]] if no provider has been initialized.
 *
 * This exactly mirrors CryptoEncryption's approach:
 * - Inherits the old libsodium-based class as fallback.
 * - Overrides each method to call CryptoHashWithCryptoLayer when providerInitialized is true.
 */
export class CryptoHash extends CryptoHashWithLibsodium {
    /**
     * @inheritdoc
     */
    public static override async verify(
        content: ICoreBuffer,
        hash: ICoreBuffer,
        algorithm: CryptoHashAlgorithm
    ): Promise<boolean> {
        if (providerInitialized) {
            return await CryptoHashWithCryptoLayer.verify(
                { providerName: "SoftwareProvider" },
                content,
                hash,
                algorithm
            );
        }
        return super.verify(content, hash, algorithm);
    }

    /**
     * @inheritdoc
     */
    public static override async hash(content: ICoreBuffer, algorithm: CryptoHashAlgorithm): Promise<CoreBuffer> {
        if (providerInitialized) {
            return await CryptoHashWithCryptoLayer.hash({ providerName: "SoftwareProvider" }, content, algorithm);
        }
        return super.hash(content, algorithm);
    }

    /**
     * @inheritdoc
     */
    public static override async sha256(content: string, hash?: string): Promise<string | boolean> {
        if (providerInitialized) {
            return await CryptoHashWithCryptoLayer.sha256(content, hash);
        }
        return super.sha256(content, hash);
    }

    /**
     * @inheritdoc
     */
    public static override async sha512(content: string, hash?: string): Promise<string | boolean> {
        if (providerInitialized) {
            return await CryptoHashWithCryptoLayer.sha512(content, hash);
        }
        return super.sha512(content, hash);
    }
}
