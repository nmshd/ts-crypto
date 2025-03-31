import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoSerializable } from "../CryptoSerializable";
import { CryptoExchangeKeypairHandle } from "../crypto-layer/exchange/CryptoExchangeKeypairHandle";
import {
    CryptoExchangePrivateKey,
    ICryptoExchangePrivateKey,
    ICryptoExchangePrivateKeySerialized
} from "./CryptoExchangePrivateKey";
import {
    CryptoExchangePublicKey,
    ICryptoExchangePublicKey,
    ICryptoExchangePublicKeySerialized
} from "./CryptoExchangePublicKey";

/**
 * Interface defining the serialized form of CryptoExchangeKeypair.
 */
export interface ICryptoExchangeKeypairSerialized extends ISerialized {
    pub: ICryptoExchangePublicKeySerialized;
    prv: ICryptoExchangePrivateKeySerialized;
}

/**
 * Interface defining the structure of CryptoExchangeKeypair.
 */
export interface ICryptoExchangeKeypair extends ISerializable {
    publicKey: ICryptoExchangePublicKey;
    privateKey: ICryptoExchangePrivateKey;
}

/**
 * The original libsodium-based implementation preserved for backward compatibility.
 */
@type("CryptoExchangeKeypairWithLibsodium")
export class CryptoExchangeKeypairWithLibsodium
    extends CryptoSerializable
    implements ICryptoExchangeKeypair, IClearable
{
    @validate()
    @serialize()
    public publicKey: CryptoExchangePublicKey;

    @validate()
    @serialize()
    public privateKey: CryptoExchangePrivateKey;

    /**
     * Serializes the keypair into its JSON representation.
     *
     * @param verbose - If true, includes the "@type" property in the output.
     * @returns The serialized representation conforming to {@link ICryptoExchangeKeypairSerialized}.
     */
    public override toJSON(verbose = true): ICryptoExchangeKeypairSerialized {
        const obj: ICryptoExchangeKeypairSerialized = {
            pub: this.publicKey.toJSON(false),
            prv: this.privateKey.toJSON(false)
        };
        if (verbose) {
            obj["@type"] = "CryptoExchangeKeypairWithLibsodium";
        }

        return obj;
    }

    /**
     * Clears the sensitive data contained in this keypair.
     */
    public clear(): void {
        this.publicKey.clear();
        this.privateKey.clear();
    }

    /**
     * Pre-processes the input object to normalize key aliases and validate key properties.
     *
     * @param value - The raw input object.
     * @returns The normalized and validated object.
     * @throws {@link CryptoError} if algorithms of private and public key do not match.
     */
    protected static override preFrom(value: any): any {
        if (value.pub) {
            value = {
                publicKey: value.pub,
                privateKey: value.prv
            };
        }

        if (value.privateKey.algorithm !== value.publicKey.algorithm) {
            throw new CryptoError(
                CryptoErrorCode.ExchangeWrongAlgorithm,
                "Algorithms of private and public key do not match."
            );
        }

        return value;
    }

    /**
     * Creates an instance of {@link CryptoExchangeKeypairWithLibsodium} from a plain object or instance.
     *
     * @param value - An object conforming to {@link ICryptoExchangeKeypair} or an instance.
     * @returns An instance of {@link CryptoExchangeKeypairWithLibsodium}.
     */
    public static from(
        value: CryptoExchangeKeypairWithLibsodium | ICryptoExchangeKeypair
    ): CryptoExchangeKeypairWithLibsodium {
        return this.fromAny(value);
    }

    /**
     * Deserializes a JSON object into a {@link CryptoExchangeKeypairWithLibsodium} instance.
     *
     * @param value - The JSON object conforming to {@link ICryptoExchangeKeypairSerialized}.
     * @returns An instance of {@link CryptoExchangeKeypairWithLibsodium}.
     */
    public static fromJSON(value: ICryptoExchangeKeypairSerialized): CryptoExchangeKeypairWithLibsodium {
        return this.fromAny(value);
    }

    /**
     * Deserializes a Base64 encoded string into a {@link CryptoExchangeKeypairWithLibsodium} instance.
     *
     * @param value - The Base64 encoded string.
     * @returns An instance of {@link CryptoExchangeKeypairWithLibsodium}.
     */
    public static fromBase64(value: string): CryptoExchangeKeypairWithLibsodium {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}

/**
 * Extended class that supports handle-based keys if the crypto-layer provider is available.
 * Otherwise, it falls back to the libsodium-based implementation.
 */
@type("CryptoExchangeKeypair")
export class CryptoExchangeKeypair extends CryptoExchangeKeypairWithLibsodium {
    /**
     * Overrides `toJSON` to produce `@type: "CryptoExchangeKeypair"`.
     *
     * @param verbose - If true, includes the "@type" property in the output.
     * @returns The serialized representation with the extended type.
     */
    public override toJSON(verbose = true): ICryptoExchangeKeypairSerialized {
        const obj: ICryptoExchangeKeypairSerialized = {
            pub: this.publicKey.toJSON(false),
            prv: this.privateKey.toJSON(false)
        };
        if (verbose) {
            obj["@type"] = "CryptoExchangeKeypair";
        }

        return obj;
    }

    /**
     * Creates a new CryptoExchangeKeypair from a crypto-layer handle.
     */
    public static fromHandle(handle: CryptoExchangeKeypairHandle): CryptoExchangeKeypair {
        return handle as unknown as CryptoExchangeKeypair;
    }

    /**
     * Creates an instance of {@link CryptoExchangeKeypair} from a plain object or instance.
     *
     * @param value - An object conforming to {@link ICryptoExchangeKeypair} or an instance.
     * @returns An instance of {@link CryptoExchangeKeypair}.
     */
    public static override from(value: CryptoExchangeKeypair | ICryptoExchangeKeypair): CryptoExchangeKeypair {
        if (value instanceof CryptoExchangeKeypairHandle) {
            return value as unknown as CryptoExchangeKeypair;
        }

        const base = super.fromAny(value);
        if (base instanceof CryptoExchangeKeypair) {
            return base;
        }

        const extended = new CryptoExchangeKeypair();
        extended.publicKey = base.publicKey;
        extended.privateKey = base.privateKey;
        return extended;
    }

    /**
     * Deserializes a JSON object into a {@link CryptoExchangeKeypair} instance.
     *
     * @param value - The JSON object conforming to {@link ICryptoExchangeKeypairSerialized}.
     * @returns An instance of {@link CryptoExchangeKeypair}.
     */
    public static override fromJSON(value: ICryptoExchangeKeypairSerialized): CryptoExchangeKeypair {
        const base = super.fromJSON(value);
        const extended = new CryptoExchangeKeypair();
        extended.publicKey = base.publicKey;
        extended.privateKey = base.privateKey;
        return extended;
    }

    /**
     * Deserializes a Base64 encoded string into a {@link CryptoExchangeKeypair} instance.
     *
     * @param value - The Base64 encoded string.
     * @returns An instance of {@link CryptoExchangeKeypair}.
     */
    public static override fromBase64(value: string): CryptoExchangeKeypair {
        const base = super.fromBase64(value);
        const extended = new CryptoExchangeKeypair();
        extended.publicKey = base.publicKey;
        extended.privateKey = base.privateKey;
        return extended;
    }
}
