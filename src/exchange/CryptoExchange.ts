import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "../CoreBuffer";
import { getProvider, ProviderIdentifier } from "../crypto-layer/CryptoLayerProviders";
import { CryptoExchangeWithCryptoLayer } from "../crypto-layer/exchange/CryptoExchange";
import { CryptoExchangeKeypairHandle } from "../crypto-layer/exchange/CryptoExchangeKeypairHandle";
import { CryptoExchangePublicKeyHandle } from "../crypto-layer/exchange/CryptoExchangePublicKeyHandle";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { SodiumWrapper } from "../SodiumWrapper";
import { CryptoExchangeKeypair } from "./CryptoExchangeKeypair";
import { CryptoExchangePrivateKey } from "./CryptoExchangePrivateKey";
import { CryptoExchangePublicKey } from "./CryptoExchangePublicKey";
import { CryptoExchangeSecrets } from "./CryptoExchangeSecrets";

/**
 * The key exchange algorithm to use.
 */
export const enum CryptoExchangeAlgorithm {
    // eslint-disable-next-line @typescript-eslint/naming-convention
    ECDH_P256 = 1,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    ECDH_P521 = 2,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    ECDH_X25519 = 3
}

export class CryptoExchangeWithLibsodium {
    public static async generateKeypair(
        algorithm: CryptoExchangeAlgorithm = CryptoExchangeAlgorithm.ECDH_X25519
    ): Promise<CryptoExchangeKeypair> {
        let privateKeyBuffer: Uint8Array;
        let publicKeyBuffer: Uint8Array;

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

        const privateKey = CryptoExchangePrivateKey.from({
            algorithm,
            privateKey: CoreBuffer.from(privateKeyBuffer)
        });
        const publicKey = CryptoExchangePublicKey.from({
            algorithm,
            publicKey: CoreBuffer.from(publicKeyBuffer)
        });
        return CryptoExchangeKeypair.from({ publicKey, privateKey });
    }

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
        return CryptoExchangeSecrets.from({
            receivingKey: CoreBuffer.from(sharedKey.sharedRx),
            transmissionKey: CoreBuffer.from(sharedKey.sharedTx),
            algorithm: algorithm
        });
    }

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
        } catch (e: any) {
            throw new CryptoError(CryptoErrorCode.ExchangeKeyDerivation, `${e}`);
        }
        return CryptoExchangeSecrets.from({
            receivingKey: CoreBuffer.from(sharedKey.sharedRx),
            transmissionKey: CoreBuffer.from(sharedKey.sharedTx),
            algorithm: algorithm
        });
    }
}

let providerInitialized = false;

export function initCryptoExchange(providerIdent: ProviderIdentifier): void {
    if (getProvider(providerIdent)) {
        providerInitialized = true;
    }
}

/**
 * Extended CryptoExchange class.
 *
 * The methods accept a keypair whose private key may be either a traditional (libsodium-generated)
 * key (an instance of CryptoExchangePrivateKey) or a crypto-layer–backed key (an instance of
 * CryptoExchangeKeypairHandle). Similarly, the public key parameters may be either type.
 * Based on the key type (as determined by a helper property such as isCryptoLayerKey),
 * the corresponding implementation is called.
 */
export class CryptoExchange extends CryptoExchangeWithLibsodium {
    public static async generateKeypairHandle(
        providerIdent: ProviderIdentifier,
        spec: KeyPairSpec
    ): Promise<CryptoExchangeKeypairHandle> {
        return await CryptoExchangeWithCryptoLayer.generateKeypair(providerIdent, spec);
    }

    public static override async deriveRequestor(
        requestorKeypair: CryptoExchangeKeypair | CryptoExchangeKeypairHandle,
        templatorPublicKey: CryptoExchangePublicKey | CryptoExchangePublicKeyHandle,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoExchangeSecrets> {
        if (providerInitialized && (requestorKeypair as any).privateKey?.isCryptoLayerKey) {
            return await CryptoExchangeWithCryptoLayer.deriveRequestor(
                requestorKeypair as any,
                templatorPublicKey as any,
                algorithm
            );
        }
        if (!(requestorKeypair as any).privateKey.isCryptoLayerKey) {
            return await super.deriveRequestor(
                requestorKeypair as CryptoExchangeKeypair,
                templatorPublicKey as CryptoExchangePublicKey,
                algorithm
            );
        }
        throw new CryptoError(
            CryptoErrorCode.ExchangeWrongAlgorithm,
            "Mismatch in key types: expected traditional key."
        );
    }

    public static override async deriveTemplator(
        templatorKeypair: CryptoExchangeKeypair | CryptoExchangeKeypairHandle,
        requestorPublicKey: CryptoExchangePublicKey | CryptoExchangePublicKeyHandle,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoExchangeSecrets> {
        if (providerInitialized && (templatorKeypair as any).privateKey?.isCryptoLayerKey) {
            return await CryptoExchangeWithCryptoLayer.deriveTemplator(
                templatorKeypair as any,
                requestorPublicKey as any,
                algorithm
            );
        }
        if (!(templatorKeypair as any).privateKey.isCryptoLayerKey) {
            return await super.deriveTemplator(
                templatorKeypair as CryptoExchangeKeypair,
                requestorPublicKey as CryptoExchangePublicKey,
                algorithm
            );
        }
        throw new CryptoError(
            CryptoErrorCode.ExchangeWrongAlgorithm,
            "Mismatch in key types: expected traditional key."
        );
    }
}
