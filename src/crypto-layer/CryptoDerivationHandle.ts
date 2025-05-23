import { KDF, KeySpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer, ICoreBuffer } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { getProvider, ProviderIdentifier } from "./CryptoLayerProviders";
import { CryptoSecretKeyHandle } from "./encryption/CryptoSecretKeyHandle";

export class CryptoDerivationHandle {
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
        const provider = getProvider(providerIdent);

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
    public static async deriveKeyFromBaseKeyHandle(
        baseKey: CryptoSecretKeyHandle,
        keyId: number,
        context: string
    ): Promise<CryptoSecretKeyHandle> {
        const bytes = CoreBuffer.fromUtf8(`id:${keyId};ctx:${context}`);

        let keyHandle;
        try {
            keyHandle = await baseKey.keyHandle.deriveKey(bytes.buffer);
        } catch (e) {
            throw new CryptoError(
                CryptoErrorCode.CalKeyDerivation,
                `Failed to derive key from base key.`,
                undefined,
                e as Error,
                CryptoDerivationHandle.deriveKeyFromBaseKeyHandle
            );
        }

        return await CryptoSecretKeyHandle.fromProviderAndKeyHandle(baseKey.provider, keyHandle);
    }
}
