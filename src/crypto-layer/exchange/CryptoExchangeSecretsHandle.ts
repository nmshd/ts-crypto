import { serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../../CoreBuffer";
import { CryptoSerializableAsync } from "../../CryptoSerializable";
import { CryptoEncryptionAlgorithm } from "../../encryption/CryptoEncryption";
import { CryptoSecretKeyHandle } from "../encryption/CryptoSecretKeyHandle";

/**
 * Interface for the serialized form of CryptoExchangeSecretsHandle.
 */
export interface ICryptoExchangeSecretsHandleSerialized {
    alg: CryptoEncryptionAlgorithm;
    rx: string;
    tx: string;
    "@type"?: string;
}

/**
 * Interface defining the structure of CryptoExchangeSecretsHandle.
 */
export interface ICryptoExchangeSecretsHandle {
    algorithm: CryptoEncryptionAlgorithm;
    receivingKey: CryptoSecretKeyHandle;
    transmissionKey: CryptoSecretKeyHandle;
}

/**
 * Handle-based implementation of exchange secrets for the crypto layer.
 */
@type("CryptoExchangeSecretsHandle")
export class CryptoExchangeSecretsHandle
    extends CryptoSerializableAsync
    implements ICryptoExchangeSecretsHandle, IClearable
{
    @validate()
    @serialize()
    public algorithm: CryptoEncryptionAlgorithm;

    @validate()
    @serialize()
    public receivingKey: CryptoSecretKeyHandle;

    @validate()
    @serialize()
    public transmissionKey: CryptoSecretKeyHandle;

    /**
     * Serializes the exchange secrets handle into its JSON representation.
     *
     * @param verbose - If true, includes the "@type" property in the output.
     * @returns A Promise that resolves to the serialized representation.
     */
    public override async toJSON(verbose = true): Promise<ICryptoExchangeSecretsHandleSerialized> {
        const rxBuffer = await this.receivingKey.keyHandle.extractKey();
        const txBuffer = await this.transmissionKey.keyHandle.extractKey();

        return {
            rx: CoreBuffer.from(rxBuffer).toBase64URL(),
            tx: CoreBuffer.from(txBuffer).toBase64URL(),
            alg: this.algorithm,
            "@type": verbose ? "CryptoExchangeSecretsHandle" : undefined
        };
    }

    /**
     * Clears the sensitive data contained in this exchange secrets handle.
     */
    public clear(): void {
        this.receivingKey.clear();
        this.transmissionKey.clear();
    }

    /**
     * Serializes the handle to a JSON string.
     *
     * @param verbose - If true, includes type information in the serialized output.
     * @returns A Promise that resolves to the JSON string representation.
     */
    public override serialize(verbose = true): string {
        const json = this.toJSON(verbose);
        return JSON.stringify(json);
    }

    /**
     * Serializes the handle to Base64 encoding.
     *
     * @param verbose - If true, includes type information in the serialized output.
     * @returns A Promise that resolves to Base64 encoded string representation.
     */
    public override toBase64(verbose = true): string {
        const serialized = this.serialize(verbose);
        return CoreBuffer.utf8_base64(serialized);
    }

    /**
     * Creates an instance of CryptoExchangeSecretsHandle from a plain object or instance.
     *
     * @param value - An object conforming to ICryptoExchangeSecretsHandle or an instance.
     * @returns A Promise that resolves to a new instance of CryptoExchangeSecretsHandle.
     */
    public static async from(
        value: CryptoExchangeSecretsHandle | ICryptoExchangeSecretsHandle
    ): Promise<CryptoExchangeSecretsHandle> {
        return await this.fromAny(value);
    }

    /**
     * Pre-processes the input object to normalize key aliases.
     *
     * @param value - The raw input object.
     * @returns The normalized object.
     */
    protected static override preFrom(value: any): any {
        if (value.rx) {
            value = {
                algorithm: value.alg,
                receivingKey: value.rx,
                transmissionKey: value.tx
            };
        }
        return value;
    }

    /**
     * Deserializes a JSON object into a CryptoExchangeSecretsHandle instance.
     *
     * @param value - The JSON object to deserialize.
     * @returns A Promise that resolves to a new instance of CryptoExchangeSecretsHandle.
     */
    public static async fromJSON(value: ICryptoExchangeSecretsHandleSerialized): Promise<CryptoExchangeSecretsHandle> {
        return await this.fromAny(value);
    }

    /**
     * Deserializes a Base64 encoded string into a CryptoExchangeSecretsHandle instance.
     *
     * @param value - The Base64 encoded string.
     * @returns A Promise that resolves to a new instance of CryptoExchangeSecretsHandle.
     */
    public static async fromBase64(value: string): Promise<CryptoExchangeSecretsHandle> {
        return await this.deserialize(CoreBuffer.base64_utf8(value));
    }

    /**
     * Creates a new CryptoExchangeSecretsHandle from raw key buffers.
     *
     * @param receivingKey - The raw receiving key buffer.
     * @param transmissionKey - The raw transmission key buffer.
     * @param algorithm - The encryption algorithm to use.
     * @param providerName - The crypto provider name to use.
     * @returns A Promise that resolves to a new instance of CryptoExchangeSecretsHandle.
     */
    public static async fromRawKeys(
        receivingKey: CoreBuffer,
        transmissionKey: CoreBuffer,
        algorithm: CryptoEncryptionAlgorithm,
        providerName: string
    ): Promise<CryptoExchangeSecretsHandle> {
        const secrets = new CryptoExchangeSecretsHandle();
        secrets.algorithm = algorithm;

        // Create secret key handles for both keys
        const rxKeyHandle = await CryptoSecretKeyHandle.importRawKeyIntoHandle(
            { providerName },
            receivingKey,
            // eslint-disable-next-line @typescript-eslint/naming-convention
            { cipher: "XChaCha20Poly1305", signing_hash: "Sha2_256", ephemeral: true },
            algorithm
        );

        const txKeyHandle = await CryptoSecretKeyHandle.importRawKeyIntoHandle(
            { providerName },
            transmissionKey,
            // eslint-disable-next-line @typescript-eslint/naming-convention
            { cipher: "XChaCha20Poly1305", signing_hash: "Sha2_256", ephemeral: true },
            algorithm
        );

        secrets.receivingKey = rxKeyHandle;
        secrets.transmissionKey = txKeyHandle;

        return secrets;
    }
}
