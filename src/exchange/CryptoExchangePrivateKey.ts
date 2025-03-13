import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoPrivateKey } from "../CryptoPrivateKey";
import { SodiumWrapper } from "../SodiumWrapper";
import { ProviderIdentifier, getProvider } from "../crypto-layer/CryptoLayerProviders";
import { CryptoExchangePrivateKeyHandle } from "../crypto-layer/exchange/CryptoExchangePrivateKeyHandle";
import { CryptoExchangeAlgorithm } from "./CryptoExchange";
import { CryptoExchangePublicKey } from "./CryptoExchangePublicKey";
import { CryptoExchangeValidation } from "./CryptoExchangeValidation";

/**
 * The original libsodium-based exchange private key interface and serialization form.
 */
export interface ICryptoExchangePrivateKeySerialized extends ISerialized {
    alg: number;
    prv: string;
}

export interface ICryptoExchangePrivateKey extends ISerializable {
    algorithm: CryptoExchangeAlgorithm;
    privateKey: ICoreBuffer;
}

/**
 * The original libsodium-based exchange private key class.
 * By default, it uses libsodium to derive the public key. The `isCryptoLayerKey` getter returns false.
 */
@type("CryptoExchangePrivateKey")
export class CryptoExchangePrivateKey extends CryptoPrivateKey implements ICryptoExchangePrivateKey, IClearable {
    @validate()
    @serialize()
    public override algorithm: CryptoExchangeAlgorithm;

    @validate()
    @serialize()
    public override privateKey: CoreBuffer;

    public override toJSON(verbose = true): ICryptoExchangePrivateKeySerialized {
        return {
            prv: this.privateKey.toBase64URL(),
            alg: this.algorithm,
            "@type": verbose ? "CryptoExchangePrivateKey" : undefined
        };
    }

    public clear(): void {
        this.privateKey.clear();
    }

    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    /**
     * Derives the public key from the private key using libsodium.
     * Subclasses may override this to delegate to the crypto-layer if desired.
     */
    public async toPublicKey(): Promise<CryptoExchangePublicKey> {
        let publicKey: Uint8Array;
        switch (this.algorithm) {
            case CryptoExchangeAlgorithm.ECDH_X25519:
                try {
                    publicKey = (await SodiumWrapper.ready()).crypto_scalarmult_base(this.privateKey.buffer);
                } catch (e) {
                    throw new CryptoError(CryptoErrorCode.ExchangeKeyGeneration, `${e}`);
                }
                break;
            default:
                throw new CryptoError(CryptoErrorCode.NotYetImplemented);
        }
        return CryptoExchangePublicKey.from({
            algorithm: this.algorithm,
            publicKey: CoreBuffer.from(publicKey)
        });
    }

    public static override from(value: CryptoExchangePrivateKey | ICryptoExchangePrivateKey): CryptoExchangePrivateKey {
        return this.fromAny(value);
    }

    protected static override preFrom(value: any): any {
        if (value.alg) {
            value = {
                algorithm: value.alg,
                privateKey: CoreBuffer.fromBase64URL(value.prv)
            };
        }
        CryptoExchangeValidation.checkExchangeAlgorithm(value.algorithm);
        CryptoExchangeValidation.checkExchangePrivateKey(value.privateKey, value.algorithm, "privateKey");
        return value;
    }

    public static fromJSON(value: ICryptoExchangePrivateKeySerialized): CryptoExchangePrivateKey {
        return this.fromAny(value);
    }

    public static override fromBase64(value: string): CryptoExchangePrivateKey {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }

    /**
     * Indicates whether this key was created via the crypto-layer or libsodium. For this base class, always false.
     */
    public get isCryptoLayerKey(): boolean {
        return false;
    }
}

/**
 * A flag indicating whether a crypto-layer provider is initialized.
 * We mirror the style of the encryption extension, which does the same.
 */
let cryptoLayerProviderInitialized = false;

/**
 * Initializes the crypto-layer usage for exchange private keys, if a provider is available.
 */
export function initCryptoExchangePrivateKey(providerIdent: ProviderIdentifier): void {
    if (getProvider(providerIdent)) {
        cryptoLayerProviderInitialized = true;
    }
}

/**
 * Extended class that uses the crypto-layer for deriving the public key
 * if `isCryptoLayerKey` is true and a provider is initialized. Otherwise, it falls
 * back to the original (libsodium) method via super.toPublicKey().
 */
@type("CryptoExchangePrivateKeyCryptoLayer")
export class CryptoExchangePrivateKeyCryptoLayer
    extends CryptoExchangePrivateKey
    implements ICryptoExchangePrivateKey, IClearable
{
    /**
     * Overridden method that checks if a crypto-layer provider is active
     * and if this key is a crypto-layer key. If so, it delegates to the
     * crypto-layer handle. Otherwise, it calls super.toPublicKey().
     */
    public override async toPublicKey(): Promise<CryptoExchangePublicKey> {
        if (cryptoLayerProviderInitialized && this.isCryptoLayerKey) {
            // Cast to the handle type and delegate
            const privateKeyHandle = this as unknown as CryptoExchangePrivateKeyHandle;
            const publicKeyHandle = await privateKeyHandle.toPublicKey();
            return CryptoExchangePublicKey.from({
                algorithm: this.algorithm,
                publicKey: CoreBuffer.from(publicKeyHandle.keyPairHandle.extractKey())
            });
        }
        if (!this.isCryptoLayerKey) {
            // Fallback to the libsodium-based method from the parent class
            return await super.toPublicKey();
        }
        // If there's a mismatch, throw an error (mirroring the encryption extension style).
        throw new CryptoError(
            CryptoErrorCode.ExchangeWrongAlgorithm,
            "Mismatch in key types: expected a libsodium key or a fully initialized crypto-layer key."
        );
    }

    /**
     * For a crypto-layer key, we assume some property like 'keyPairHandle' is present.
     */
    public override get isCryptoLayerKey(): boolean {
        return (this as any).keyPairHandle !== undefined;
    }
}
