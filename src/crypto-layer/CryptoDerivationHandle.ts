/* eslint-disable @typescript-eslint/naming-convention */
import { KDF, KeySpec } from "@nmshd/rs-crypto-types";
import { CryptoDerivationAlgorithm } from "src/CryptoDerivation";
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

export class CryptoDerivationHandle {
    private static async deriveKeyHandleFromPassword<T extends BaseKeyHandle>(
        constructor: BaseKeyHandleConstructor<T>,
        providerIdent: ProviderIdentifier,
        password: ICoreBuffer,
        salt: ICoreBuffer,
        keySpecOfResultingKey: KeySpec,
        kdfOptions: KDF
    ): Promise<T> {
        const provider = getProvider(providerIdent);
        // TODO update according to deriveDeviceBoundKeyHandleFromPassword
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

        return await constructor.fromProviderAndKeyHandle(provider, keyHandle);
    }

    /**
     * Derive an ephemeral {@link DeviceBoundDerivedKeyHandle} from a password.
     */
    public static async deriveDeviceBoundKeyHandleFromPassword(
        providerIdent: ProviderIdentifier,
        password: ICoreBuffer,
        salt: ICoreBuffer,
        encryptionAlgorithm: CryptoEncryptionAlgorithm,
        hashAlgorithm: CryptoHashAlgorithm,
        derivationAlgorithm: CryptoDerivationAlgorithm,
        iterations: number,
        memlimit: number,
        parallelism: number
    ): Promise<DeviceBoundDerivedKeyHandle> {
        // TODO: Move to separate utility class
        let kdfParameters: KDF;
        switch (derivationAlgorithm) {
            case CryptoDerivationAlgorithm.ARGON2I:
                kdfParameters = {
                    Argon2d: {
                        iterations,
                        memory: memlimit,
                        parallelism
                    }
                };
                break;
            case CryptoDerivationAlgorithm.ARGON2ID:
                kdfParameters = {
                    Argon2id: {
                        iterations,
                        memory: memlimit,
                        parallelism
                    }
                };
                break;
        }
        return await CryptoDerivationHandle.deriveKeyHandleFromPassword<DeviceBoundDerivedKeyHandle>(
            DeviceBoundDerivedKeyHandle,
            providerIdent,
            password,
            salt,
            {
                cipher: CryptoLayerUtils.cipherFromCryptoEncryptionAlgorithm(encryptionAlgorithm),
                signing_hash: CryptoLayerUtils.cryptoHashFromCryptoHashAlgorithm(hashAlgorithm),
                ephemeral: true,
                non_exportable: false
            },
            kdfParameters
        );
    }

    /**
     * Derive an ephemeral {@link PortableDerivedKeyHandle} from a password.
     */
    public static async derivePortableKeyHandleFromPassword(
        providerIdent: ProviderIdentifier,
        password: ICoreBuffer,
        salt: ICoreBuffer,
        keySpecOfResultingKey: KeySpec,
        kdfOptions: KDF
    ): Promise<PortableDerivedKeyHandle> {
        // TODO update according to deriveDeviceBoundKeyHandleFromPassword
        return await CryptoDerivationHandle.deriveKeyHandleFromPassword<PortableDerivedKeyHandle>(
            PortableDerivedKeyHandle,
            providerIdent,
            password,
            salt,
            keySpecOfResultingKey,
            kdfOptions
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
