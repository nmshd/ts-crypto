import { ISerializable, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, ICoreBuffer } from "../CoreBuffer";
import { CryptoDerivation } from "../CryptoDerivation";
import { CryptoSerializable } from "../CryptoSerializable";
import { CryptoCipher } from "../encryption/CryptoCipher";
import { CryptoEncryption } from "../encryption/CryptoEncryption";
import { CryptoSecretKey, ICryptoSecretKey } from "../encryption/CryptoSecretKey";
import { CryptoExchange } from "../exchange/CryptoExchange";
import { CryptoExchangeKeypair, ICryptoExchangeKeypair } from "../exchange/CryptoExchangeKeypair";
import { CryptoExchangePublicKey, ICryptoExchangePublicKey } from "../exchange/CryptoExchangePublicKey";
import { CryptoHashAlgorithm } from "../hash/CryptoHash";
import { CryptoRandom } from "../random/CryptoRandom";
import { CryptoSignature } from "../signature/CryptoSignature";
import { CryptoSignatureKeypair, ICryptoSignatureKeypair } from "../signature/CryptoSignatureKeypair";
import { CryptoSignaturePublicKey, ICryptoSignaturePublicKey } from "../signature/CryptoSignaturePublicKey";
import { CryptoSignatures } from "../signature/CryptoSignatures";
import { CryptoRelationshipPublicRequest } from "./CryptoRelationshipPublicRequest";

export interface ICryptoRelationshipRequestSecrets extends ISerializable {
    id?: string;
    exchangeKeypair: ICryptoExchangeKeypair;
    signatureKeypair: ICryptoSignatureKeypair;
    ephemeralKeypair: ICryptoExchangeKeypair;
    peerIdentityKey: ICryptoSignaturePublicKey;
    peerExchangeKey: ICryptoExchangePublicKey;
    secretKey: ICryptoSecretKey;
    nonce: ICoreBuffer;
}

@type("CryptoRelationshipRequestSecrets")
export class CryptoRelationshipRequestSecrets extends CryptoSerializable implements ICryptoRelationshipRequestSecrets {
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

    public static from(value: ICryptoRelationshipRequestSecrets): CryptoRelationshipRequestSecrets {
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
