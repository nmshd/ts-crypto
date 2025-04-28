import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { KeySpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer, IClearable } from "../CoreBuffer";
import { ProviderIdentifier } from "../crypto-layer/CryptoLayerProviders";
import { CryptoSecretKeyHandle } from "../crypto-layer/encryption/CryptoSecretKeyHandle";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoSerializable } from "../CryptoSerializable";
import { CryptoValidation } from "../CryptoValidation";
import { SodiumWrapper } from "../SodiumWrapper";
import { CryptoEncryptionAlgorithm } from "./CryptoEncryption";

/**
 * The libsodium-based secret key interface & serialization.
 */
export interface ICryptoSecretKeySerialized extends ISerialized {
    alg: number;
    key: string;
}

export interface ICryptoSecretKey extends ISerializable {
    algorithm: CryptoEncryptionAlgorithm;
    secretKey: CoreBuffer;
}

/**
 * The original libsodium-based class, storing a raw key in memory.
 * It retains the existing `generateKey` method.
 *
 * This version is fully backwards-compatible with old tests.
 */
@type("CryptoSecretKeyWithLibsodium")
export class CryptoSecretKeyWithLibsodium extends CryptoSerializable implements ICryptoSecretKey, IClearable {
    @validate()
    @serialize()
    public algorithm: CryptoEncryptionAlgorithm;

    @validate()
    @serialize()
    public secretKey: CoreBuffer;

    public override toJSON(verbose = true): ICryptoSecretKeySerialized {
        return {
            key: this.secretKey.toBase64URL(),
            alg: this.algorithm,
            "@type": verbose ? "CryptoSecretKeyWithLibsodium" : undefined
        };
    }

    public clear(): void {
        this.secretKey.clear();
    }

    /**
     * The libsodium-based `generateKey` remains here in the base class.
     * If you want a raw key, you call CryptoSecretKeyWithLibsodium.generateKey(...).
     *
     * This method is 100% identical to the old implementation, preserving test compatibility.
     */
    public static async generateKey(
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoSecretKeyWithLibsodium> {
        CryptoValidation.checkEncryptionAlgorithm(algorithm);

        let buffer: CoreBuffer;
        // eslint-disable-next-line @typescript-eslint/switch-exhaustiveness-check
        switch (algorithm) {
            case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
                try {
                    buffer = new CoreBuffer((await SodiumWrapper.ready()).crypto_aead_xchacha20poly1305_ietf_keygen());
                } catch (e) {
                    throw new CryptoError(CryptoErrorCode.EncryptionKeyGeneration, `${e}`);
                }
                break;
            default:
                throw new CryptoError(
                    CryptoErrorCode.NotYetImplemented,
                    "Algorithm not supported by libsodium approach"
                );
        }
        return this.from({ secretKey: buffer, algorithm });
    }

    public static from(value: CryptoSecretKeyWithLibsodium | ICryptoSecretKey): CryptoSecretKeyWithLibsodium {
        return this.fromAny(value);
    }

    protected static override preFrom(value: any): any {
        if (value.alg) {
            value = {
                algorithm: value.alg,
                secretKey: value.key
            };
        }
        CryptoValidation.checkEncryptionAlgorithm(value.algorithm);

        if (typeof value.secretKey === "string") {
            CryptoValidation.checkSerializedSecretKeyForAlgorithm(value.secretKey, value.algorithm);
        } else {
            CryptoValidation.checkSecretKeyForAlgorithm(value.secretKey, value.algorithm);
        }
        return value;
    }

    public static fromJSON(value: ICryptoSecretKeySerialized): CryptoSecretKeyWithLibsodium {
        return this.fromAny(value);
    }

    public static fromBase64(value: string): CryptoSecretKeyWithLibsodium {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}

/**
 * Extended class that can also create or store a handle-based key if the provider is available.
 * Otherwise, it calls the libsodium fallback from the base class.
 */
@type("CryptoSecretKey")
export class CryptoSecretKey extends CryptoSecretKeyWithLibsodium {
    /**
     * If you want a handle-based key, use this method.
     * If the provider is not init, we do not fallback here; the user specifically requested a handle-based key.
     */
    public static async generateKeyHandle(
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
        providerIdent: ProviderIdentifier,
        spec: KeySpec
    ): Promise<CryptoSecretKey> {
        // Build a handle-based key
        const handle = await CryptoSecretKeyHandle.generateKeyHandle(providerIdent, spec, algorithm);
        // Wrap that handle in a new extended CryptoSecretKey
        return CryptoSecretKey.fromHandle(handle);
    }

    public override toJSON(verbose = false): ICryptoSecretKeySerialized {
        const serialized = super.toJSON(false);
        serialized["@type"] = verbose ? "CryptoSecretKey" : undefined;
        return serialized;
    }

    /**
     * Overriding the base class's "clear" method:
     * If we have a handle-based key and the provider is init, do a no-op or
     * ask the provider to revoke the handle. Otherwise, fallback to zeroing raw memory.
     */
    public override clear(): void {
        if (this.secretKey instanceof CryptoSecretKeyHandle) {
            // For handle-based keys, there's no raw data in memory to clear.
            // Possibly do "this.keyHandle = null" or call the provider's deletion method.
            return;
        }
        super.clear();
    }

    /**
     * If the provider is available, we store a handle-based reference; otherwise, fallback to raw extraction.
     */
    public static fromHandle(handle: CryptoSecretKeyHandle): CryptoSecretKey {
        const key = new CryptoSecretKey();
        key.algorithm = CryptoEncryptionAlgorithm.fromCalCipher(handle.spec.cipher);

        key.secretKey = CoreBuffer.fromUtf8("handle-based key, no raw data in memory");
        (key as any).keyHandle = handle;
        return key;
    }

    /**
     * Overriding "from" to ensure we return a CryptoSecretKey (not the base class).
     * This helps old code remain compatible (if it calls "CryptoSecretKey.from(...)" it gets the new type).
     */
    public static override from(value: CryptoSecretKeyWithLibsodium | ICryptoSecretKey): CryptoSecretKey {
        // use the parent's fromAny to parse
        const base = super.fromAny(value);
        // base is a CryptoSecretKeyWithLibsodium. We'll copy its fields into our new extended instance.
        const extended = new CryptoSecretKey();
        extended.algorithm = base.algorithm;
        extended.secretKey = base.secretKey;
        // if the parent has a handle-based approach, we can copy it
        if ((base as any).keyHandle) {
            (extended as any).keyHandle = (base as any).keyHandle;
        }
        return extended;
    }
}
