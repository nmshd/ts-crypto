/* eslint-disable @typescript-eslint/naming-convention */
import { KDF, KeySpec } from "@nmshd/rs-crypto-types";
import { CryptoDerivationAlgorithm } from "src/CryptoDerivation";
import { CryptoValidation } from "src/CryptoValidation";
import { CryptoEncryptionAlgorithm } from "src/encryption/CryptoEncryption";
import { CryptoHashAlgorithm } from "src/hash/CryptoHash";
import { CoreBuffer, ICoreBuffer } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { getProvider, ProviderIdentifier } from "./CryptoLayerProviders";
import { CryptoLayerUtils } from "./CryptoLayerUtils";
import { BaseKeyHandle, BaseKeyHandleConstructor } from "./encryption/BaseKeyHandle";
import { DeviceBoundDerivedKeyHandle } from "./encryption/DeviceBoundDerivedKeyHandle";
import { DeviceBoundKeyHandle } from "./encryption/DeviceBoundKeyHandle";
import { PortableDerivedKeyHandle } from "./encryption/PortableDerivedKeyHandle";
import { PortableKeyHandle } from "./encryption/PortableKeyHandle";

interface DeriveKeyHandleFromPasswordParameters {
    providerIdent: ProviderIdentifier;
    password: ICoreBuffer;
    salt: ICoreBuffer;
    resultingKeyEncryptionAlgorithm: CryptoEncryptionAlgorithm;
    resultingKeyHashAlgorithm: CryptoHashAlgorithm;
    derivationAlgorithm: CryptoDerivationAlgorithm;
    derivationIterations: number;
    derivationMemoryLimit: number;
    derivationParallelism: number;
}

export class CryptoDerivationHandle {
    private static async deriveKeyHandleFromPassword<T extends BaseKeyHandle>(
        constructor: BaseKeyHandleConstructor<T>,
        {
            providerIdent,
            password,
            salt,
            derivationAlgorithm,
            derivationIterations,
            derivationMemoryLimit,
            derivationParallelism
        }: DeriveKeyHandleFromPasswordParameters,
        keySpecOfResultingKey: KeySpec
    ): Promise<T> {
        CryptoValidation.checkBuffer(new CoreBuffer(salt), 8, 64, "salt", true);

        const provider = getProvider(providerIdent);

        const kdfParameters: KDF = CryptoLayerUtils.kdfFromCryptoDerivation(
            derivationAlgorithm,
            derivationIterations,
            derivationMemoryLimit,
            derivationParallelism
        );

        let keyHandle;
        try {
            keyHandle = await provider.deriveKeyFromPassword(
                password.toUtf8(),
                salt.buffer,
                keySpecOfResultingKey,
                kdfParameters
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

        return await constructor.fromProviderAndKeyHandle(provider, keyHandle);
    }

    /**
     * Derive an ephemeral {@link DeviceBoundDerivedKeyHandle} from a password.
     */
    public static async deriveDeviceBoundKeyHandleFromPassword(
        parameters: DeriveKeyHandleFromPasswordParameters
    ): Promise<DeviceBoundDerivedKeyHandle> {
        const keySpec: KeySpec = {
            cipher: CryptoLayerUtils.cipherFromCryptoEncryptionAlgorithm(parameters.resultingKeyEncryptionAlgorithm),
            signing_hash: CryptoLayerUtils.cryptoHashFromCryptoHashAlgorithm(parameters.resultingKeyHashAlgorithm),
            ephemeral: true,
            non_exportable: true
        };

        return await CryptoDerivationHandle.deriveKeyHandleFromPassword<DeviceBoundDerivedKeyHandle>(
            DeviceBoundDerivedKeyHandle,
            parameters,
            keySpec
        );
    }

    /**
     * Derive an ephemeral {@link PortableDerivedKeyHandle} from a password.
     */
    public static async derivePortableKeyHandleFromPassword(
        parameters: DeriveKeyHandleFromPasswordParameters
    ): Promise<PortableDerivedKeyHandle> {
        const keySpec: KeySpec = {
            cipher: CryptoLayerUtils.cipherFromCryptoEncryptionAlgorithm(parameters.resultingKeyEncryptionAlgorithm),
            signing_hash: CryptoLayerUtils.cryptoHashFromCryptoHashAlgorithm(parameters.resultingKeyHashAlgorithm),
            ephemeral: true,
            non_exportable: false
        };

        return await CryptoDerivationHandle.deriveKeyHandleFromPassword<PortableDerivedKeyHandle>(
            PortableDerivedKeyHandle,
            parameters,
            keySpec
        );
    }

    private static async deriveKeyFromBaseKeyHandle<T extends BaseKeyHandle, R extends BaseKeyHandle>(
        constructor: BaseKeyHandleConstructor<R>,
        baseKey: T,
        keyId: number,
        context: string
    ): Promise<R> {
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

        return await constructor.fromProviderAndKeyHandle(baseKey.provider, keyHandle);
    }

    /**
     * Derive an ephemeral {@link DeviceBoundDerivedKeyHandle} from a {@link DeviceBoundKeyHandle} with the same algorithms.
     */
    public static async deriveDeviceBoundKeyHandle(
        baseKey: DeviceBoundKeyHandle,
        keyId: number,
        context: string
    ): Promise<DeviceBoundDerivedKeyHandle> {
        return await CryptoDerivationHandle.deriveKeyFromBaseKeyHandle<
            DeviceBoundKeyHandle,
            DeviceBoundDerivedKeyHandle
        >(DeviceBoundDerivedKeyHandle, baseKey, keyId, context);
    }

    /**
     * Derive an ephemeral {@link PortableDerivedKeyHandle} from a {@link PortableKeyHandle} with the same algorithms.
     */
    public static async derivePortableKeyHandle(
        baseKey: PortableKeyHandle,
        keyId: number,
        context: string
    ): Promise<PortableDerivedKeyHandle> {
        return await CryptoDerivationHandle.deriveKeyFromBaseKeyHandle<PortableKeyHandle, PortableDerivedKeyHandle>(
            PortableDerivedKeyHandle,
            baseKey,
            keyId,
            context
        );
    }
}
