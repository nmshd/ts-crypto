import { ISerializable, serialize, type, validate } from "@js-soft/ts-serval";
import { CryptoSignaturePrivateKeyHandle } from "src/crypto-layer/signature/CryptoSignaturePrivateKeyHandle";
import { CryptoSignaturesWithCryptoLayer } from "src/crypto-layer/signature/CryptoSignatures";
import { CryptoExchange } from "src/exchange/CryptoExchange";
import { CoreBuffer, ICoreBuffer } from "../CoreBuffer";
import { CryptoDerivation } from "../CryptoDerivation";
import { CryptoSerializable } from "../CryptoSerializable";
import { CryptoCipher } from "../encryption/CryptoCipher";
import { CryptoEncryption } from "../encryption/CryptoEncryption";
import { CryptoSecretKey } from "../encryption/CryptoSecretKey";
import { CryptoExchangeKeypair } from "../exchange/CryptoExchangeKeypair";
import { CryptoExchangePublicKey } from "../exchange/CryptoExchangePublicKey";
import { CryptoHashAlgorithm } from "../hash/CryptoHash";
import { CryptoRandom } from "../random/CryptoRandom";
import { CryptoSignature } from "../signature/CryptoSignature";
import { CryptoSignatureKeypair } from "../signature/CryptoSignatureKeypair";
import { CryptoSignaturePublicKey } from "../signature/CryptoSignaturePublicKey";
import { CryptoSignatures } from "../signature/CryptoSignatures";
import { CryptoRelationshipPublicRequest } from "./CryptoRelationshipPublicRequest";

/**
 * The original interface describing libsodium-based request secrets.
 */
export interface ICryptoRelationshipRequestSecrets extends ISerializable {
    id?: string;
    exchangeKeypair: CryptoExchangeKeypair;
    signatureKeypair: CryptoSignatureKeypair;
    ephemeralKeypair: CryptoExchangeKeypair;
    peerIdentityKey: CryptoSignaturePublicKey;
    peerExchangeKey: CryptoExchangePublicKey;
    secretKey: CryptoSecretKey;
    nonce: ICoreBuffer;
}

/**
 * The original libsodium-based class, preserving your old logic exactly.
 */
@type("CryptoRelationshipRequestSecretsWithLibsodium")
export class CryptoRelationshipRequestSecretsWithLibsodium
    extends CryptoSerializable
    implements ICryptoRelationshipRequestSecrets
{
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    @validate()
    @serialize({ alias: "exc" })
    public exchangeKeypair: CryptoExchangeKeypair;

    @validate()
    @serialize({ alias: "eph" })
    public ephemeralKeypair: CryptoExchangeKeypair;

    @validate()
    @serialize({ alias: "sig" })
    public signatureKeypair: CryptoSignatureKeypair;

    @validate()
    @serialize({ alias: "pik" })
    public peerIdentityKey: CryptoSignaturePublicKey;

    @validate()
    @serialize({ alias: "pxk" })
    public peerExchangeKey: CryptoExchangePublicKey;

    @validate()
    @serialize({ alias: "key" })
    public secretKey: CryptoSecretKey;

    @validate()
    @serialize({ alias: "nnc" })
    public nonce: CoreBuffer;

    public static from(value: ICryptoRelationshipRequestSecrets): CryptoRelationshipRequestSecretsWithLibsodium {
        return this.fromAny(value);
    }

    public async sign(
        content: CoreBuffer,
        algorithm: CryptoHashAlgorithm = CryptoHashAlgorithm.SHA256
    ): Promise<CryptoSignature> {
        return await CryptoSignatures.sign(content, this.signatureKeypair.privateKey, algorithm);
    }

    public async verifyOwn(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        return await CryptoSignatures.verify(content, signature, this.signatureKeypair.publicKey);
    }

    public async verifyPeerIdentity(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        return await CryptoSignatures.verify(content, signature, this.peerIdentityKey);
    }

    public async encryptRequest(content: CoreBuffer): Promise<CryptoCipher> {
        return await CryptoEncryption.encrypt(content, this.secretKey);
    }

    public async decryptRequest(cipher: CryptoCipher): Promise<CoreBuffer> {
        return await CryptoEncryption.decrypt(cipher, this.secretKey);
    }

    public toPublicRequest(): CryptoRelationshipPublicRequest {
        return CryptoRelationshipPublicRequest.from({
            id: this.id,
            exchangeKey: this.exchangeKeypair.publicKey,
            signatureKey: this.signatureKeypair.publicKey,
            ephemeralKey: this.ephemeralKeypair.publicKey,
            nonce: this.nonce
        });
    }

    public static async fromPeer(
        peerExchangeKey: CryptoExchangePublicKey,
        peerIdentityKey: CryptoSignaturePublicKey
    ): Promise<CryptoRelationshipRequestSecrets> {
        const [exchangeKeypair, ephemeralKeypair, signatureKeypair, nonce] = await Promise.all([
            CryptoExchange.generateKeypair(),
            CryptoExchange.generateKeypair(),
            CryptoSignatures.generateKeypair(),
            CryptoRandom.bytes(24)
        ]);

        const masterKey = await CryptoExchange.deriveRequestor(ephemeralKeypair, peerExchangeKey);
        const secretKey = await CryptoDerivation.deriveKeyFromBase(masterKey.transmissionKey, 1, "REQTMP01");

        return CryptoRelationshipRequestSecrets.from({
            exchangeKeypair: exchangeKeypair,
            ephemeralKeypair: ephemeralKeypair,
            signatureKeypair: signatureKeypair,
            peerExchangeKey: peerExchangeKey,
            peerIdentityKey: peerIdentityKey,
            secretKey: secretKey,
            nonce: nonce
        });
    }
}

/**
 * A simple flag indicating if a crypto-layer approach is available for request secrets.
 */
let requestSecretsProviderInitialized = false;

/**
 * Call this if a provider is available for handle-based usage of request secrets.
 */
export function initCryptoRelationshipRequestSecrets(): void {
    requestSecretsProviderInitialized = true;
}

/**
 * The new extended class that can also do handle-based usage if the provider is available.
 */
@type("CryptoRelationshipRequestSecrets")
export class CryptoRelationshipRequestSecrets extends CryptoRelationshipRequestSecretsWithLibsodium {
    public static override from(value: ICryptoRelationshipRequestSecrets): CryptoRelationshipRequestSecrets {
        const base = super.fromAny(value);
        const extended = new CryptoRelationshipRequestSecrets();
        extended.id = base.id;
        extended.exchangeKeypair = base.exchangeKeypair;
        extended.ephemeralKeypair = base.ephemeralKeypair;
        extended.signatureKeypair = base.signatureKeypair;
        extended.peerIdentityKey = base.peerIdentityKey;
        extended.peerExchangeKey = base.peerExchangeKey;
        extended.secretKey = base.secretKey;
        extended.nonce = base.nonce;
        return extended;
    }

    public static override async fromPeer(
        peerExchangeKey: CryptoExchangePublicKey,
        peerIdentityKey: CryptoSignaturePublicKey
    ): Promise<CryptoRelationshipRequestSecrets> {
        if (requestSecretsProviderInitialized) {
            const base = await super.fromPeer(peerExchangeKey, peerIdentityKey);
            return this.from(base);
        }
        const base = await super.fromPeer(peerExchangeKey, peerIdentityKey);
        return this.from(base);
    }

    public override async sign(content: CoreBuffer, algorithm = CryptoHashAlgorithm.SHA256): Promise<CryptoSignature> {
        if (requestSecretsProviderInitialized && (this.signatureKeypair as any)) {
            return await CryptoSignaturesWithCryptoLayer.sign(
                content,
                await CryptoSignaturePrivateKeyHandle.fromAny(this.signatureKeypair.privateKey),
                "Id"
            );
        }
        // fallback
        return await super.sign(content, algorithm);
    }
}
