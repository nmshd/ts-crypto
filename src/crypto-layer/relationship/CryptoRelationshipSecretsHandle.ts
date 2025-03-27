import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CryptoExchangeAlgorithm } from "src/exchange/CryptoExchange";
import { CryptoExchangeSecrets } from "src/exchange/CryptoExchangeSecrets";
import { CoreBuffer } from "../../CoreBuffer";
import { CryptoDerivation } from "../../CryptoDerivation";
import { CryptoError } from "../../CryptoError";
import { CryptoErrorCode } from "../../CryptoErrorCode";
import { CryptoSerializableAsync } from "../../CryptoSerializable";
import { CryptoCipher } from "../../encryption/CryptoCipher";
import { CryptoEncryptionAlgorithm } from "../../encryption/CryptoEncryption";
import { CryptoHashAlgorithm } from "../../hash/CryptoHash";
import { CryptoRelationshipType } from "../../relationship/CryptoRelationshipType";
import { CryptoSignature } from "../../signature/CryptoSignature";
import { CryptoStateType } from "../../state/CryptoStateType";
import { getProviderOrThrow } from "../CryptoLayerProviders";
import { asymSpecFromCryptoAlgorithm } from "../CryptoLayerUtils";
import { CryptoEncryptionWithCryptoLayer } from "../encryption/CryptoEncryption";
import { CryptoSecretKeyHandle } from "../encryption/CryptoSecretKeyHandle";
import { CryptoExchangeWithCryptoLayer } from "../exchange/CryptoExchange";
import {
    CryptoExchangeKeypairHandle,
    ICryptoExchangeKeypairHandleSerialized
} from "../exchange/CryptoExchangeKeypairHandle";
import {
    CryptoExchangePublicKeyHandle,
    ICryptoExchangePublicKeyHandleSerialized
} from "../exchange/CryptoExchangePublicKeyHandle";
import {
    CryptoSignatureKeypairHandle,
    ICryptoSignatureKeypairHandleSerialized
} from "../signature/CryptoSignatureKeypair";
import {
    CryptoSignaturePublicKeyHandle,
    ICryptoSignaturePublicKeyHandleSerialized
} from "../signature/CryptoSignaturePublicKeyHandle";
import { CryptoSignaturesWithCryptoLayer } from "../signature/CryptoSignatures";
import { CryptoPrivateStateHandle, ICryptoPrivateStateHandleSerialized } from "../state/CryptoPrivateStateHandle";
import { CryptoRelationshipPublicRequestHandle } from "./CryptoRelationshipPublicRequestHandle";
import { CryptoRelationshipPublicResponseHandle } from "./CryptoRelationshipPublicResponseHandle";
import { CryptoRelationshipRequestSecretsHandle } from "./CryptoRelationshipRequestSecretsHandle";

/**
 * Interface defining the serialized form of {@link CryptoRelationshipSecretsHandle}.
 */
export interface ICryptoRelationshipSecretsHandleSerialized extends ISerialized {
    id?: string;
    typ: CryptoRelationshipType;
    exc: ICryptoExchangeKeypairHandleSerialized;
    sig: ICryptoSignatureKeypairHandleSerialized;
    tx: ICryptoPrivateStateHandleSerialized;
    rx: ICryptoPrivateStateHandleSerialized;
    pxk: ICryptoExchangePublicKeyHandleSerialized;
    psk: ICryptoSignaturePublicKeyHandleSerialized;
    ptk: ICryptoExchangePublicKeyHandleSerialized;
    pik?: ICryptoSignaturePublicKeyHandleSerialized;
    rsk: string;
}

/**
 * Interface defining the structure of {@link CryptoRelationshipSecretsHandle}.
 * The requestSecretKey is maintained as a raw buffer rather than a handle.
 */
export interface ICryptoRelationshipSecretsHandle extends ISerializable {
    id?: string;
    type: CryptoRelationshipType;
    exchangeKeypair: CryptoExchangeKeypairHandle;
    signatureKeypair: CryptoSignatureKeypairHandle;
    transmitState: CryptoPrivateStateHandle;
    receiveState: CryptoPrivateStateHandle;
    peerExchangeKey: CryptoExchangePublicKeyHandle;
    peerSignatureKey: CryptoSignaturePublicKeyHandle;
    peerTemplateKey: CryptoExchangePublicKeyHandle;
    peerIdentityKey?: CryptoSignaturePublicKeyHandle;
    requestSecretKey: CoreBuffer;
}

/**
 * Provides handle-based relationship secrets functionalities using the crypto layer.
 * This class encapsulates various cryptographic handles and states, enabling secure
 * signing, encryption, and verification for relationships.
 */
@type("CryptoRelationshipSecretsHandle")
export class CryptoRelationshipSecretsHandle
    extends CryptoSerializableAsync
    implements ICryptoRelationshipSecretsHandle
{
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    @validate()
    @serialize({ alias: "typ" })
    public type: CryptoRelationshipType;

    @validate()
    @serialize({ alias: "exc" })
    public exchangeKeypair: CryptoExchangeKeypairHandle;

    @validate()
    @serialize({ alias: "sig" })
    public signatureKeypair: CryptoSignatureKeypairHandle;

    @validate()
    @serialize({ alias: "tx" })
    public transmitState: CryptoPrivateStateHandle;

    @validate()
    @serialize({ alias: "rx" })
    public receiveState: CryptoPrivateStateHandle;

    @validate()
    @serialize({ alias: "pxk" })
    public peerExchangeKey: CryptoExchangePublicKeyHandle;

    @validate()
    @serialize({ alias: "psk" })
    public peerSignatureKey: CryptoSignaturePublicKeyHandle;

    @validate()
    @serialize({ alias: "ptk" })
    public peerTemplateKey: CryptoExchangePublicKeyHandle;

    @validate({ nullable: true })
    @serialize({ alias: "pik" })
    public peerIdentityKey?: CryptoSignaturePublicKeyHandle;

    /**
     * Ephemeral request secret key stored as a raw `CoreBuffer` (not a handle).
     */
    @validate()
    @serialize({ alias: "rsk" })
    public requestSecretKey: CoreBuffer;

    /**
     * Serializes sub-handles and converts the raw request secret key to a base64 representation.
     *
     * @param verbose - If true, includes the "@type" property in the output.
     * @returns A Promise that resolves to the serialized form {@link ICryptoRelationshipSecretsHandleSerialized}.
     */
    public override async toJSON(verbose = true): Promise<ICryptoRelationshipSecretsHandleSerialized> {
        return {
            exc: this.exchangeKeypair.toJSON(false),
            sig: this.signatureKeypair.toJSON(false),
            tx: await this.transmitState.toJSON(false),
            rx: await this.receiveState.toJSON(false),
            pxk: this.peerExchangeKey.toJSON(false),
            psk: this.peerSignatureKey.toJSON(false),
            ptk: this.peerTemplateKey.toJSON(false),
            pik: this.peerIdentityKey?.toJSON(false),
            rsk: this.requestSecretKey.toBase64URL(),
            typ: this.type,
            id: this.id,
            "@type": verbose ? "CryptoRelationshipSecretsHandle" : undefined
        };
    }

    /**
     * Creates an instance of {@link CryptoRelationshipSecretsHandle} from a plain object or an instance.
     *
     * @param value - An object conforming to {@link ICryptoRelationshipSecretsHandle} or an instance.
     * @returns A Promise that resolves to a new instance of {@link CryptoRelationshipSecretsHandle}.
     */
    public static async from(
        value: CryptoRelationshipSecretsHandle | ICryptoRelationshipSecretsHandle
    ): Promise<CryptoRelationshipSecretsHandle> {
        return await this.fromAny(value);
    }

    /**
     * Pre-processes the input object to normalize key aliases.
     *
     * @param value - The raw input object.
     * @returns The normalized object.
     */
    protected static override preFrom(value: any): any {
        if (value.exc) {
            value = {
                exchangeKeypair: value.exc,
                signatureKeypair: value.sig,
                transmitState: value.tx,
                receiveState: value.rx,
                peerExchangeKey: value.pxk,
                peerSignatureKey: value.psk,
                peerTemplateKey: value.ptk,
                peerIdentityKey: value.pik,
                requestSecretKey: value.rsk,
                type: value.typ,
                id: value.id
            };
        }
        return value;
    }

    /**
     * Internal helper to derive secrets using persistent keypair handles.
     * Replicates the logic previously in deriveRequestor/deriveTemplator before
     * they were specialized for DHExchange handles.
     */
    private static async _deriveSecretsFromPersistentKeys(
        localKeyPair: CryptoExchangeKeypairHandle,
        peerPublicKey: CryptoExchangePublicKeyHandle,
        role: "Requestor" | "Templator",
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.AES256_GCM
    ): Promise<CryptoExchangeSecrets> {
        const exchangeAlgorithm = localKeyPair.privateKey.spec.asym_spec;
        if (peerPublicKey.spec.asym_spec !== exchangeAlgorithm) {
            throw new Error(
                `Algorithm mismatch: Peer public key (${peerPublicKey.spec.asym_spec}) vs Local private key (${exchangeAlgorithm}).`
            );
        }

        let exchangeAlgorithmMapped: CryptoExchangeAlgorithm;
        // eslint-disable-next-line @typescript-eslint/switch-exhaustiveness-check
        switch (exchangeAlgorithm) {
            case "P256":
                exchangeAlgorithmMapped = CryptoExchangeAlgorithm.ECDH_P256;
                break;
            case "Curve25519":
                exchangeAlgorithmMapped = CryptoExchangeAlgorithm.ECDH_X25519;
                break;
            default:
                throw new Error(`Unsupported key exchange algorithm: ${exchangeAlgorithm}`);
        }

        // Get provider using info from the local key handle
        const provider = getProviderOrThrow({ providerName: localKeyPair.privateKey.providerName });

        // Create the spec needed for dhExchangeFromKeys
        // Assuming createDHExchangeSpec is accessible or recreate its logic
        const dhExchangeSpec: KeyPairSpec = {
            // eslint-disable-next-line @typescript-eslint/naming-convention
            asym_spec: asymSpecFromCryptoAlgorithm(exchangeAlgorithmMapped),
            ephemeral: true,
            cipher: null,
            // eslint-disable-next-line @typescript-eslint/naming-convention
            signing_hash: "Sha2_256",
            // eslint-disable-next-line @typescript-eslint/naming-convention
            non_exportable: false
        };

        // Extract necessary key bytes
        const localPrivateKeyBytes = await localKeyPair.privateKey.keyPairHandle.extractKey();
        const localPublicKeyBytes = await localKeyPair.publicKey.keyPairHandle.getPublicKey();
        const peerPublicKeyBytes = await peerPublicKey.keyPairHandle.getPublicKey();

        try {
            // Create temporary DH context from persistent keys
            const tempDHExchange = await provider.dhExchangeFromKeys(
                localPublicKeyBytes,
                localPrivateKeyBytes,
                dhExchangeSpec
            );

            // Derive session keys based on role
            const [rx, tx] =
                role === "Requestor"
                    ? await tempDHExchange.deriveServerSessionKeys(peerPublicKeyBytes)
                    : await tempDHExchange.deriveClientSessionKeys(peerPublicKeyBytes);

            // Create secrets object
            const secrets = CryptoExchangeSecrets.from({
                receivingKey: CoreBuffer.from(rx),
                transmissionKey: CoreBuffer.from(tx),
                algorithm: algorithm
            });

            return secrets;
        } catch (e) {
            throw new Error(`Derivation from persistent keys failed: ${e instanceof Error ? e.message : String(e)}`);
        }
    }

    /**
     * Deserializes a JSON object into a {@link CryptoRelationshipSecretsHandle} instance.
     *
     * @param value - The JSON object conforming to {@link ICryptoRelationshipSecretsHandleSerialized}.
     * @returns A Promise that resolves to an instance of {@link CryptoRelationshipSecretsHandle}.
     */
    public static async fromJSON(
        value: ICryptoRelationshipSecretsHandleSerialized
    ): Promise<CryptoRelationshipSecretsHandle> {
        return await this.fromAny(value);
    }

    /**
     * Deserializes a base64 encoded string into a {@link CryptoRelationshipSecretsHandle} instance.
     *
     * @param value - The base64 encoded string.
     * @returns A Promise that resolves to an instance of {@link CryptoRelationshipSecretsHandle}.
     */
    public static async fromBase64(value: string): Promise<CryptoRelationshipSecretsHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }

    /**
     * Signs the provided content using the handle-based signature key.
     *
     * @param content - The content to sign as a {@link CoreBuffer}.
     * @param _algorithm - The hash algorithm to be used (defaults to SHA256).
     * @returns A Promise that resolves to a {@link CryptoSignature} of the content.
     */
    public async sign(
        content: CoreBuffer,
        _algorithm: CryptoHashAlgorithm = CryptoHashAlgorithm.SHA256
    ): Promise<CryptoSignature> {
        return await CryptoSignaturesWithCryptoLayer.sign(content, this.signatureKeypair.privateKey, this.id);
    }

    /**
     * Verifies a signature against the provided content using the handle's own signature key.
     *
     * @param content - The content to verify.
     * @param signature - The signature to verify.
     * @returns A Promise that resolves to a boolean indicating the verification result.
     */
    public async verifyOwn(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        return await CryptoSignaturesWithCryptoLayer.verify(content, signature, this.signatureKeypair.privateKey);
    }

    /**
     * Verifies a signature against the provided content using the peer's signature key.
     *
     * @param content - The content to verify.
     * @param signature - The signature to verify.
     * @returns A Promise that resolves to a boolean indicating the verification result.
     */
    public async verifyPeer(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        return await CryptoSignaturesWithCryptoLayer.verify(content, signature, this.peerSignatureKey);
    }

    /**
     * Verifies a signature against the provided content using the peer's identity key.
     *
     * @param content - The content to verify.
     * @param signature - The signature to verify.
     * @returns A Promise that resolves to a boolean indicating the verification result.
     * @throws {@link CryptoError} if the peer identity key is not set.
     */
    public async verifyPeerIdentity(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        if (!this.peerIdentityKey) {
            throw new CryptoError(CryptoErrorCode.RelationshipNoPeer, "No peer identity key is set in this handle.");
        }
        return await CryptoSignaturesWithCryptoLayer.verify(content, signature, this.peerIdentityKey);
    }

    /**
     * Encrypts the given content using the local transmit state.
     *
     * @param content - The {@link CoreBuffer} content to encrypt.
     * @returns A Promise that resolves to a {@link CryptoCipher} containing the encrypted data.
     */
    public async encrypt(content: CoreBuffer): Promise<CryptoCipher> {
        return await this.transmitState.encrypt(content);
    }

    /**
     * Decrypts a cipher using the local transmit state.
     *
     * @param cipher - The {@link CryptoCipher} to decrypt.
     * @returns A Promise that resolves to the decrypted {@link CoreBuffer} content.
     */
    public async decryptOwn(cipher: CryptoCipher): Promise<CoreBuffer> {
        return await this.transmitState.decrypt(cipher);
    }

    /**
     * Decrypts a cipher using the local receive state.
     *
     * @param cipher - The {@link CryptoCipher} to decrypt.
     * @param omitCounterCheck - Optional flag to omit counter check during decryption.
     * @returns A Promise that resolves to the decrypted {@link CoreBuffer} content.
     */
    public async decryptPeer(cipher: CryptoCipher, omitCounterCheck = false): Promise<CoreBuffer> {
        return await this.receiveState.decrypt(cipher, omitCounterCheck);
    }

    /**
     * Decrypts a cipher using the raw request secret key.
     *
     * @param cipher - The {@link CryptoCipher} to decrypt.
     * @returns A Promise that resolves to the decrypted {@link CoreBuffer} content.
     */
    public async decryptRequest(cipher: CryptoCipher): Promise<CoreBuffer> {
        // The requestSecretKey is a raw ephemeral key; pass the raw buffer to the crypto layer.
        return await CryptoEncryptionWithCryptoLayer.decrypt(
            cipher,
            await CryptoSecretKeyHandle.from(this.requestSecretKey)
        );
    }

    /**
     * Creates a handle-based public response using the local transmit state and signature key.
     *
     * @returns An instance of {@link CryptoRelationshipPublicResponseHandle} containing public keys and state.
     */
    public toPublicResponse(): CryptoRelationshipPublicResponseHandle {
        const responseHandle = new CryptoRelationshipPublicResponseHandle();
        responseHandle.exchangeKey = this.exchangeKeypair.publicKey;
        responseHandle.signatureKey = this.signatureKeypair.publicKey;
        responseHandle.state = this.transmitState.toPublicState();
        return responseHandle;
    }

    /**
     * Creates a relationship secrets handle from a public response and local request secrets.
     * (Requestor role)
     *
     * @param response - The {@link CryptoRelationshipPublicResponseHandle} from the counterparty.
     * @param request - The {@link CryptoRelationshipRequestSecretsHandle} containing local request secrets.
     * @returns A Promise that resolves to a new instance of {@link CryptoRelationshipSecretsHandle}.
     */
    public static async fromRelationshipResponse(
        response: CryptoRelationshipPublicResponseHandle,
        request: CryptoRelationshipRequestSecretsHandle
    ): Promise<CryptoRelationshipSecretsHandle> {
        const signatureKeypair = request.signatureKeypair;
        const exchangeKeypair = request.exchangeKeypair;
        const requestSecretKey = request.secretKey;
        const peerExchangeKey = response.exchangeKey;
        const peerPublicTransmitState = response.state;
        const peerSignatureKey = response.signatureKey;
        const peerIdentityKey = request.peerIdentityKey;
        const peerTemplateKey = request.peerExchangeKey;
        const ownType = CryptoRelationshipType.Requestor;

        const derivedKey = await CryptoRelationshipSecretsHandle._deriveSecretsFromPersistentKeys(
            exchangeKeypair, // Local persistent keypair handle
            peerExchangeKey, // Peer public key handle
            "Requestor" // Role for key derivation
        );

        const [derivedTx, derivedRx] = await Promise.all([
            CryptoDerivation.deriveKeyFromBase(derivedKey.transmissionKey, 1, "RELREQ01"),
            CryptoDerivation.deriveKeyFromBase(derivedKey.receivingKey, 1, "RELTEM01")
        ]);

        const receiveState = await CryptoPrivateStateHandle.from({
            nonce: peerPublicTransmitState.nonce.clone(),
            counter: 0,
            algorithm: peerPublicTransmitState.algorithm,
            stateType: peerPublicTransmitState.stateType,
            id: peerPublicTransmitState.id,
            secretKeyHandle: await CryptoSecretKeyHandle.from(derivedRx.secretKey)
        });

        const transmitState = await CryptoPrivateStateHandle.from({
            nonce: request.nonce.clone(),
            counter: 0,
            algorithm: CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
            stateType: CryptoStateType.Transmit,
            secretKeyHandle: await CryptoSecretKeyHandle.from(derivedTx.secretKey)
        });

        const relationshipSecretHandle = new CryptoRelationshipSecretsHandle();
        relationshipSecretHandle.id = request.id;
        relationshipSecretHandle.type = ownType;
        relationshipSecretHandle.exchangeKeypair = exchangeKeypair;
        relationshipSecretHandle.signatureKeypair = signatureKeypair;
        relationshipSecretHandle.transmitState = transmitState;
        relationshipSecretHandle.receiveState = receiveState;
        relationshipSecretHandle.peerExchangeKey = peerExchangeKey;
        relationshipSecretHandle.peerSignatureKey = peerSignatureKey;
        relationshipSecretHandle.peerTemplateKey = peerTemplateKey;
        relationshipSecretHandle.peerIdentityKey = peerIdentityKey;
        relationshipSecretHandle.requestSecretKey = CoreBuffer.from(requestSecretKey);

        return relationshipSecretHandle;
    }

    /**
     * Creates a relationship secrets handle from a public request and a local template exchange key.
     * (Templator role)
     *
     * @param request - The {@link CryptoRelationshipPublicRequestHandle} from the counterparty.
     * @param templateExchangeKeypair - The local template {@link CryptoExchangeKeypairHandle}.
     * @returns A Promise that resolves to a new instance of {@link CryptoRelationshipSecretsHandle}.
     */
    public static async fromRelationshipRequest(
        request: CryptoRelationshipPublicRequestHandle,
        templateExchangeKeypair: CryptoExchangeKeypairHandle
    ): Promise<CryptoRelationshipSecretsHandle> {
        const peerExchangeKey = request.exchangeKey;
        const peerTemplateKey = request.ephemeralKey;
        const peerSignatureKey = request.signatureKey;

        const providerName = templateExchangeKeypair.privateKey.providerName;

        const signatureKeypair = await CryptoSignaturesWithCryptoLayer.generateKeypair(
            { providerName: providerName },
            peerSignatureKey.spec
        );
        const exchangeKeypair = await CryptoExchangeWithCryptoLayer.generateKeypair(
            { providerName: providerName },
            peerExchangeKey.spec
        );

        // Deriving persistent relationship keys
        const derivedKey = await CryptoRelationshipSecretsHandle._deriveSecretsFromPersistentKeys(
            exchangeKeypair, // Local generated persistent keypair handle
            peerExchangeKey, // Peer persistent public key handle
            "Templator" // Role for key derivation
        );

        const [derivedTx, derivedRx] = await Promise.all([
            CryptoDerivation.deriveKeyFromBase(derivedKey.transmissionKey, 1, "RELTEM01"),
            CryptoDerivation.deriveKeyFromBase(derivedKey.receivingKey, 1, "RELREQ01")
        ]);

        const receiveState = await CryptoPrivateStateHandle.from({
            nonce: request.nonce.clone(),
            counter: 0,
            algorithm: CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
            stateType: CryptoStateType.Receive,
            secretKeyHandle: await CryptoSecretKeyHandle.from(derivedRx.secretKey)
        });

        const transmitState = await CryptoPrivateStateHandle.from({
            nonce: request.nonce.clone(),
            counter: 0,
            algorithm: CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
            stateType: CryptoStateType.Transmit,
            secretKeyHandle: await CryptoSecretKeyHandle.from(derivedTx.secretKey)
        });

        // Deriving ephemeral request secret key (Templator receives)
        const masterKey = await CryptoRelationshipSecretsHandle._deriveSecretsFromPersistentKeys(
            templateExchangeKeypair, // Local template keypair handle (persistent)
            peerTemplateKey, // Peer ephemeral public key handle
            "Templator" // Role for key derivation (Templator = Client in DH)
        );
        const ephemeralKey = await CryptoDerivation.deriveKeyFromBase(masterKey.receivingKey, 1, "REQTMP01");

        const relationshipSecretHandle = new CryptoRelationshipSecretsHandle();
        relationshipSecretHandle.id = request.id;
        relationshipSecretHandle.type = CryptoRelationshipType.Templator;
        relationshipSecretHandle.exchangeKeypair = exchangeKeypair;
        relationshipSecretHandle.signatureKeypair = signatureKeypair;
        relationshipSecretHandle.transmitState = transmitState;
        relationshipSecretHandle.receiveState = receiveState;
        relationshipSecretHandle.peerExchangeKey = peerExchangeKey;
        relationshipSecretHandle.peerSignatureKey = peerSignatureKey;
        relationshipSecretHandle.peerTemplateKey = peerTemplateKey;
        relationshipSecretHandle.peerIdentityKey = request.signatureKey;
        relationshipSecretHandle.requestSecretKey = ephemeralKey.secretKey;

        return relationshipSecretHandle;
    }

    /**
     * Creates a relationship secrets handle using the "peerNonce" approach for ephemeral derivation.
     * The ephemeral request secret key is stored as a raw buffer.
     *
     * @param peerExchangeKey - The peer's {@link CryptoExchangePublicKeyHandle}.
     * @param peerTemplateKey - The peer's template {@link CryptoExchangePublicKeyHandle}.
     * @param peerSignatureKey - The peer's {@link CryptoSignaturePublicKeyHandle}.
     * @param peerGeneratedNonce - The nonce generated by the peer as a {@link CoreBuffer}.
     * @param templateExchangeKeypair - The local template {@link CryptoExchangeKeypairHandle}.
     * @param peerIdentityKey - Optional peer identity {@link CryptoSignaturePublicKeyHandle}.
     * @param peerType - The type of peer relationship (defaults to Requestor).
     * @returns A Promise that resolves to a new instance of {@link CryptoRelationshipSecretsHandle}.
     * @throws {@link Error} if the peer type is not Requestor or Templator.
     */
    public static async fromPeerNonce(
        peerExchangeKey: CryptoExchangePublicKeyHandle,
        peerTemplateKey: CryptoExchangePublicKeyHandle, // Peer's ephemeral key in this context?
        peerSignatureKey: CryptoSignaturePublicKeyHandle,
        peerGeneratedNonce: CoreBuffer,
        templateExchangeKeypair: CryptoExchangeKeypairHandle,
        peerIdentityKey?: CryptoSignaturePublicKeyHandle,
        peerType: CryptoRelationshipType = CryptoRelationshipType.Requestor
    ): Promise<CryptoRelationshipSecretsHandle> {
        const providerName = templateExchangeKeypair.privateKey.providerName;

        const signatureKeypair = await CryptoSignaturesWithCryptoLayer.generateKeypair(
            { providerName: providerName },
            peerSignatureKey.spec
        );
        const exchangeKeypair = await CryptoExchangeWithCryptoLayer.generateKeypair(
            { providerName: providerName },
            peerExchangeKey.spec
        );

        let derivedKey;
        let ownType;
        switch (peerType) {
            case CryptoRelationshipType.Requestor:
                // If peer is Requestor, we derive as Templator
                derivedKey = await CryptoRelationshipSecretsHandle._deriveSecretsFromPersistentKeys(
                    exchangeKeypair, // Local persistent keypair
                    peerExchangeKey, // Peer persistent key
                    "Templator" // Derive as Templator if peer is Requestor
                );
                ownType = CryptoRelationshipType.Templator;
                break;
            case CryptoRelationshipType.Templator:
                // If peer is Templator, we derive as Requestor
                derivedKey = await CryptoRelationshipSecretsHandle._deriveSecretsFromPersistentKeys(
                    exchangeKeypair, // Local persistent keypair
                    peerExchangeKey, // Peer persistent key
                    "Requestor" // Derive as Requestor if peer is Templator
                );
                ownType = CryptoRelationshipType.Requestor;
                break;
            default:
                throw new Error("Invalid relationship peer type specified.");
        }

        // Derive state keys based on OWN role (Templator derives TEM, Requestor derives REQ)
        const txDerivationString = ownType === CryptoRelationshipType.Templator ? "RELTEM01" : "RELREQ01";
        const rxDerivationString = ownType === CryptoRelationshipType.Templator ? "RELREQ01" : "RELTEM01";

        const [derivedTx, derivedRx] = await Promise.all([
            CryptoDerivation.deriveKeyFromBase(derivedKey.transmissionKey, 1, txDerivationString),
            CryptoDerivation.deriveKeyFromBase(derivedKey.receivingKey, 1, rxDerivationString)
        ]);

        const receiveState = await CryptoPrivateStateHandle.from({
            nonce: peerGeneratedNonce.clone(),
            counter: 0,
            algorithm: CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
            stateType: CryptoStateType.Receive,
            secretKeyHandle: await CryptoSecretKeyHandle.from(derivedRx.secretKey)
        });

        const transmitState = await CryptoPrivateStateHandle.from({
            nonce: CoreBuffer.random(24),
            counter: 0,
            algorithm: CryptoEncryptionAlgorithm.XCHACHA20_POLY1305,
            stateType: CryptoStateType.Transmit,
            secretKeyHandle: await CryptoSecretKeyHandle.from(derivedTx.secretKey)
        });

        // Derive ephemeral request key (Templator receives)
        const masterKey = await CryptoRelationshipSecretsHandle._deriveSecretsFromPersistentKeys(
            templateExchangeKeypair, // Local template keypair handle
            peerTemplateKey, // Peer's ephemeral public key handle
            "Templator" // Role for key derivation (Templator receives)
        );
        const ephemeralKey = await CryptoDerivation.deriveKeyFromBase(masterKey.receivingKey, 1, "REQTMP01");

        return await CryptoRelationshipSecretsHandle.from({
            id: exchangeKeypair.publicKey.id,
            exchangeKeypair,
            signatureKeypair,
            receiveState,
            transmitState,
            type: ownType,
            peerExchangeKey,
            peerSignatureKey,
            peerTemplateKey,
            peerIdentityKey,
            requestSecretKey: ephemeralKey.secretKey
        });
    }
}
