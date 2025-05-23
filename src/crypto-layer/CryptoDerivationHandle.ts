import { KDF, KeySpec } from "@nmshd/rs-crypto-types";
import { ICoreBuffer } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoSerializableAsync } from "../CryptoSerializable";
import { getProviderOrThrow, ProviderIdentifier } from "./CryptoLayerProviders";
import { CryptoSecretKeyHandle } from "./encryption/CryptoSecretKeyHandle";

export class CryptoDerivationHandle extends CryptoSerializableAsync {
    /**
     * Derive an ephemeral {@link CryptoSecretKeyHandle} from a password.
     */
    public static async deriveKeyHandleFromPassword(
        providerIdent: ProviderIdentifier,
        password: ICoreBuffer,
        salt: ICoreBuffer,
        keySpecOfResultingKey: KeySpec,
        kdfOptions: KDF
    ): Promise<CryptoSecretKeyHandle> {
        const provider = getProviderOrThrow(providerIdent);

        let keyHandle;
        try {
            keyHandle = await provider.deriveKeyFromPassword(
                password.toUtf8(),
                salt.buffer,
                keySpecOfResultingKey,
                kdfOptions
            );
        } catch (e) {
            throw new CryptoError(
                CryptoErrorCode.CalKeyDerivation,
                `Provider ${await provider.providerName()} failed to derive key from password.`,
                undefined,
                e as Error,
                CryptoDerivationHandle.deriveKeyHandleFromPassword
            );
        }

        return await CryptoSecretKeyHandle.fromProviderAndKeyHandle(provider, keyHandle);
    }

    /**
     * Derive an ephemeral {@link CryptoSecretKeyHandle} from another with the same key spec and algorithm.
     */
    public static async deriveKeyHandleFromBase(
        baseKey: CryptoSecretKeyHandle,
        keyId: number,
        context: string
    ): Promise<CryptoSecretKeyHandle> {
        const encoder = new TextEncoder();
        const bytes = encoder.encode(`id:${keyId};ctx:${context}`);

        let keyHandle;
        try {
            keyHandle = await baseKey.keyHandle.deriveKey(bytes);
        } catch (e) {
            throw new CryptoError(
                CryptoErrorCode.CalKeyDerivation,
                `Failed to derive key from base key.`,
                undefined,
                e as Error,
                CryptoDerivationHandle.deriveKeyHandleFromBase
            );
        }

        return await CryptoSecretKeyHandle.fromProviderAndKeyHandle(baseKey.provider, keyHandle);
    }
}
