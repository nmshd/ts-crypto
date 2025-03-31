import { CryptoHash as RustHashAlgorithm } from "@nmshd/rs-crypto-types";
import { CoreBuffer, Encoding, ICoreBuffer } from "../../CoreBuffer";
import { CryptoError } from "../../CryptoError";
import { CryptoErrorCode } from "../../CryptoErrorCode";
import { CryptoHashAlgorithm } from "../../hash/CryptoHash";
import { getProviderOrThrow, ProviderIdentifier } from "../CryptoLayerProviders";

/**
 * Provides hashing functionalities using the Rust-based crypto layer.
 * This class is designed to replace the libsodium-based implementation,
 * leveraging the Rust-based crypto layer for enhanced security and performance.
 */
export class CryptoHashWithCryptoLayer {
    /**
     * Asynchronously hashes the given content using the specified hashing algorithm.
     *
     * @param providerIdent - The identifier for the crypto provider to be used for hashing.
     * @param content - The data to be hashed, as a {@link CoreBuffer}.
     * @param algorithm - The {@link CryptoHashAlgorithm} to use for hashing.
     * @returns A Promise that resolves to a {@link CoreBuffer} containing the hash of the content.
     * @throws {@link CryptoError} if hashing fails or if the specified algorithm is not supported.
     */
    public static async hash(
        providerIdent: ProviderIdentifier,
        content: ICoreBuffer,
        algorithm: CryptoHashAlgorithm
    ): Promise<CoreBuffer> {
        const provider = getProviderOrThrow(providerIdent);
        const rustAlgorithm = this.mapAlgorithm(algorithm);

        try {
            const hashBytes = await provider.hash(content.buffer, rustAlgorithm);
            return CoreBuffer.from(hashBytes);
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.WrongHashAlgorithm, `${e}`);
        }
    }

    /**
     * Asynchronously verifies whether the given content matches the expected hash using the specified hashing algorithm.
     *
     * @param providerIdent - The identifier for the crypto provider to be used for hashing.
     * @param content - The data to be hashed and compared, as a {@link CoreBuffer}.
     * @param expectedHash - The expected hash of the content, as a {@link CoreBuffer}.
     * @param algorithm - The {@link CryptoHashAlgorithm} to use for hashing.
     * @returns A Promise that resolves to true if the content matches the expected hash, false otherwise.
     */
    public static async verify(
        providerIdent: ProviderIdentifier,
        content: ICoreBuffer,
        expectedHash: ICoreBuffer,
        algorithm: CryptoHashAlgorithm
    ): Promise<boolean> {
        const actualHash = await this.hash(providerIdent, content, algorithm);
        return actualHash.equals(expectedHash);
    }

    /**
     * Maps the internal {@link CryptoHashAlgorithm} to the Rust-based {@link CryptoHash}.
     *
     * @param algorithm - The internal hashing algorithm to map.
     * @returns The corresponding Rust-based hashing algorithm.
     * @throws {@link CryptoError} if the algorithm is not supported.
     */
    private static mapAlgorithm(algorithm: CryptoHashAlgorithm): RustHashAlgorithm {
        switch (algorithm) {
            case CryptoHashAlgorithm.SHA256:
                return "Sha2_256";
            case CryptoHashAlgorithm.SHA512:
                return "Sha2_512";
            case CryptoHashAlgorithm.BLAKE2B:
                return "Blake2b";
            default:
                throw new CryptoError(
                    CryptoErrorCode.WrongHashAlgorithm,
                    `Hash algorithm ${algorithm} is not supported by the crypto layer.`
                );
        }
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
    public static async sha256(
        content: string,
        provider: ProviderIdentifier,
        hash?: string
    ): Promise<string | boolean> {
        const bufferContent = CoreBuffer.fromString(content, Encoding.Utf8);

        // If a hash is given, verify it
        if (hash) {
            const bufferHash = CoreBuffer.fromString(hash, Encoding.Hex);
            return await this.verify(provider, bufferContent, bufferHash, CryptoHashAlgorithm.SHA256);
        }

        // Otherwise produce a new SHA-256 hash
        const created = await this.hash(provider, bufferContent, CryptoHashAlgorithm.SHA256);
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
    public static async sha512(
        content: string,
        provider: ProviderIdentifier,
        hash?: string
    ): Promise<string | boolean> {
        const bufferContent = CoreBuffer.fromString(content, Encoding.Utf8);

        if (hash) {
            const bufferHash = CoreBuffer.fromString(hash, Encoding.Hex);
            return await this.verify(provider, bufferContent, bufferHash, CryptoHashAlgorithm.SHA512);
        }

        const created = await this.hash(provider, bufferContent, CryptoHashAlgorithm.SHA512);
        return created.toString(Encoding.Hex);
    }
}
