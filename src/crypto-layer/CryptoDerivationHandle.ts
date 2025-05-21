import { KDF, KeySpec } from "@nmshd/rs-crypto-types";
import { ICoreBuffer } from "../CoreBuffer";
import { CryptoSerializableAsync } from "../CryptoSerializable";
import { getProviderOrThrow, ProviderIdentifier } from "./CryptoLayerProviders";
import { CryptoSecretKeyHandle } from "./encryption/CryptoSecretKeyHandle";

export class CryptoDerivationHandle extends CryptoSerializableAsync {
    /** Derive an ephemeral {@link CryptoSecretKeyHandle} from a password.  */
    public static async deriveKeyHandleFromPassword(
        providerIdent: ProviderIdentifier,
        password: ICoreBuffer,
        salt: ICoreBuffer,
        keySpecOfResultingKey: KeySpec,
        kdfOptions: KDF
    ): Promise<CryptoSecretKeyHandle> {
        const provider = getProviderOrThrow(providerIdent);

        const keyHandle = await provider.deriveKeyFromPassword(
            password.toUtf8(),
            salt.buffer,
            keySpecOfResultingKey,
            kdfOptions
        );

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
        const derived = await baseKey.keyHandle.deriveKey(bytes);
        return await CryptoSecretKeyHandle.fromProviderAndKeyHandle(baseKey.provider, derived);
    }
}
