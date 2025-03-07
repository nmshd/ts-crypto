import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../../CoreBuffer";
import { CryptoSerializableAsync } from "../../CryptoSerializable";
import { CryptoCipher } from "../../encryption/CryptoCipher";
import { CryptoRandom } from "../../random/CryptoRandom";
import { CryptoSignature } from "../../signature/CryptoSignature";
import { CryptoEncryptionWithCryptoLayer } from "../encryption/CryptoEncryption";
import { CryptoSecretKeyHandle } from "../encryption/CryptoSecretKeyHandle";
import { CryptoExchangeWithCryptoLayer } from "../exchange/CryptoExchange";
import { CryptoExchangeKeypairHandle } from "../exchange/CryptoExchangeKeypairHandle";
import { CryptoExchangePublicKeyHandle } from "../exchange/CryptoExchangePublicKeyHandle";
import { CryptoSignaturePublicKeyHandle } from "../signature/CryptoSignaturePublicKeyHandle";
import { CryptoSignaturesWithCryptoLayer } from "../signature/CryptoSignatures";

/**
 * Serialized form of CryptoRelationshipPublicRequestHandle.
 */
export interface ICryptoRelationshipPublicRequestHandleSerialized extends ISerialized {
    id?: string;
    exc: any;
    sig: any;
    eph: any;
    nnc: string;
}

/**
 * Interface defining the structure of CryptoRelationshipPublicRequestHandle.
 */
export interface ICryptoRelationshipPublicRequestHandle extends ISerializable {
    id?: string;
    exchangeKey: CryptoExchangePublicKeyHandle;
    signatureKey: CryptoSignaturePublicKeyHandle;
    ephemeralKey: CryptoExchangePublicKeyHandle;
    nonce: CoreBuffer;
}

@type("CryptoRelationshipPublicRequestHandle")
export class CryptoRelationshipPublicRequestHandle
    extends CryptoSerializableAsync
    implements ICryptoRelationshipPublicRequestHandle, IClearable
{
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    @validate()
    @serialize()
    public exchangeKey: CryptoExchangePublicKeyHandle;

    @validate()
    @serialize()
    public signatureKey: CryptoSignaturePublicKeyHandle;

    @validate()
    @serialize()
    public ephemeralKey: CryptoExchangePublicKeyHandle;

    @validate()
    @serialize()
    public nonce: CoreBuffer;

    public override toJSON(verbose = true): ICryptoRelationshipPublicRequestHandleSerialized {
        return {
            exc: this.exchangeKey.toJSON(false),
            sig: this.signatureKey.toJSON(false),
            eph: this.ephemeralKey.toJSON(false),
            nnc: this.nonce.toBase64URL(),
            id: this.id,
            "@type": verbose ? "CryptoRelationshipPublicRequestHandle" : undefined
        };
    }

    public clear(): void {
        this.nonce.clear();
    }

    /** Handle-based implementation of fromPeer method */
    public static async fromPeer(
        providerName: string,
        peerExchangeKey: CryptoExchangePublicKeyHandle,
        peerSignatureKey: CryptoSignaturePublicKeyHandle
    ): Promise<CryptoRelationshipPublicRequestHandle> {
        const ephemeralKeypair: CryptoExchangeKeypairHandle = await CryptoExchangeWithCryptoLayer.generateKeypair(
            { providerName },
            peerExchangeKey.spec
        );

        const nonce = await CryptoRandom.bytes(24);

        const handle = new CryptoRelationshipPublicRequestHandle();
        handle.exchangeKey = peerExchangeKey;
        handle.signatureKey = peerSignatureKey;
        handle.ephemeralKey = ephemeralKeypair.publicKey;
        handle.nonce = nonce;

        return handle;
    }

    public static async from(
        value: CryptoRelationshipPublicRequestHandle | ICryptoRelationshipPublicRequestHandle
    ): Promise<CryptoRelationshipPublicRequestHandle> {
        return await this.fromAny(value);
    }

    protected static override preFrom(value: any): any {
        if (value.exc) {
            value = {
                exchangeKey: value.exc,
                signatureKey: value.sig,
                ephemeralKey: value.eph,
                nonce: value.nnc,
                id: value.id
            };
        }
        return value;
    }

    public static async fromJSON(
        value: ICryptoRelationshipPublicRequestHandleSerialized
    ): Promise<CryptoRelationshipPublicRequestHandle> {
        return await this.fromAny(value);
    }

    public static async fromBase64(value: string): Promise<CryptoRelationshipPublicRequestHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }

    public async verify(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        return await CryptoSignaturesWithCryptoLayer.verify(content, signature, this.signatureKey);
    }

    public async encryptRequest(content: CoreBuffer, secretKey: CryptoSecretKeyHandle): Promise<CryptoCipher> {
        return await CryptoEncryptionWithCryptoLayer.encrypt(content, secretKey);
    }

    public async decryptRequest(cipher: CryptoCipher, secretKey: CryptoSecretKeyHandle): Promise<CoreBuffer> {
        return await CryptoEncryptionWithCryptoLayer.decrypt(cipher, secretKey, this.nonce);
    }
}
