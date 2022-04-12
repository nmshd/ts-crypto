import { CoreBuffer } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { SodiumWrapper } from "../SodiumWrapper";
import { CryptoExchangeKeypair } from "./CryptoExchangeKeypair";
import { CryptoExchangePrivateKey } from "./CryptoExchangePrivateKey";
import { CryptoExchangePublicKey } from "./CryptoExchangePublicKey";
import { CryptoExchangeSecrets } from "./CryptoExchangeSecrets";

export const enum CryptoExchangeAlgorithm {
    // eslint-disable-next-line @typescript-eslint/naming-convention
    ECDH_P256 = 1,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    ECDH_P521 = 2,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    ECDH_X25519 = 3
}

export class CryptoExchange {
    /**
     * Generates a keypair for the specified key exchange algorithm
     *
     * @param algorithm The [[CryptoExchangeAlgorithm]] for which a keypair should be generated. Defaults to ECDH_X25519
     * @returns A Promise resolving into a [[CryptoExchangeKeypair]] object
     */
    public static async generateKeypair(
        algorithm: CryptoExchangeAlgorithm = CryptoExchangeAlgorithm.ECDH_X25519
    ): Promise<CryptoExchangeKeypair> {
        let privateKeyBuffer;
        let publicKeyBuffer;

        switch (algorithm as number) {
            case CryptoExchangeAlgorithm.ECDH_X25519:
                let pair;
                try {
                    pair = (await SodiumWrapper.ready()).crypto_kx_keypair();
                } catch (e: any) {
                    throw new CryptoError(CryptoErrorCode.ExchangeKeyGeneration, `${e}`);
                }
                privateKeyBuffer = pair.privateKey;
                publicKeyBuffer = pair.publicKey;
                break;
            default:
                throw new CryptoError(CryptoErrorCode.NotYetImplemented);
        }

        const privateKey = CryptoExchangePrivateKey.from({ algorithm, privateKey: CoreBuffer.from(privateKeyBuffer) });
        const publicKey = CryptoExchangePublicKey.from({ algorithm, publicKey: CoreBuffer.from(publicKeyBuffer) });
        const keypair = CryptoExchangeKeypair.from({ publicKey, privateKey });

        return keypair;
    }

    /**
     * Derives session keys from the given private exchange keypair and the given public
     * exchange keypair of another party. Please ensure, that the server/sender/from entity
     * calls the deriveRequestor method, whereas the counterparty (client/recipient/to entity)
     * needs to call the deriveTemplator method, in order to derive the working keys.
     *
     * The method derives two separate secret keys: One for transmission (transmissionKey) and
     * one for receiving (receivingKey). Please only use the respective keys for their purpose.
     *
     * @param requestorKeypair The [[CryptoExchangeKeypair]] of the sending side
     * @param templatorPublicKey The [[CryptoExchangePublicKey]] of the receiving side
     * @param algorithm The [[CryptoEncryptionAlgorithm]] algorithm for which the secret keys should
     * be generated.
     * @returns A Promise resolving into a [[CryptoExchangeSecrets]] object, containing the shared keys
     * for transmission and receiving.
     */
    public static async deriveRequestor(
        requestorKeypair: CryptoExchangeKeypair,
        templatorPublicKey: CryptoExchangePublicKey,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoExchangeSecrets> {
        let sharedKey;
        try {
            sharedKey = (await SodiumWrapper.ready()).crypto_kx_server_session_keys(
                requestorKeypair.publicKey.publicKey.buffer,
                requestorKeypair.privateKey.privateKey.buffer,
                templatorPublicKey.publicKey.buffer
            );
        } catch (e: any) {
            throw new CryptoError(CryptoErrorCode.ExchangeKeyDerivation, `${e}`);
        }

        const secrets = CryptoExchangeSecrets.from({
            receivingKey: CoreBuffer.from(sharedKey.sharedRx),
            transmissionKey: CoreBuffer.from(sharedKey.sharedTx),
            algorithm: algorithm
        });
        return secrets;
    }

    /**
     * Derives session keys from the given private exchange keypair and the given public
     * exchange keypair of another party. Please ensure, that the server/sender/from entity
     * calls the deriveRequestor method, whereas the counterparty (client/recipient/to entity)
     * needs to call the deriveTemplator method, in order to derive the working keys.
     *
     * The method derives two separate secret keys: One for transmission (transmissionKey) and
     * one for receiving (receivingKey). Please only use the respective keys for their purpose.
     *
     * @param templatorKeypair The [[CryptoExchangeKeypair]] of the receiving side
     * @param requestorPublicKey The [[CryptoExchangePublicKey]] of the sending side
     * @param algorithm The [[CryptoEncryptionAlgorithm]] algorithm for which the secret keys should
     * be generated.
     * @returns A Promise resolving into a [[CryptoExchangeSecrets]] object, containing the shared keys
     * for transmission and receiving.
     */
    public static async deriveTemplator(
        templatorKeypair: CryptoExchangeKeypair,
        requestorPublicKey: CryptoExchangePublicKey,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoExchangeSecrets> {
        let sharedKey;
        try {
            sharedKey = (await SodiumWrapper.ready()).crypto_kx_client_session_keys(
                templatorKeypair.publicKey.publicKey.buffer,
                templatorKeypair.privateKey.privateKey.buffer,
                requestorPublicKey.publicKey.buffer
            );
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.ExchangeKeyDerivation, `${e}`);
        }

        const secrets = CryptoExchangeSecrets.from({
            receivingKey: CoreBuffer.from(sharedKey.sharedRx),
            transmissionKey: CoreBuffer.from(sharedKey.sharedTx),
            algorithm: algorithm
        });
        return secrets;
    }
}
