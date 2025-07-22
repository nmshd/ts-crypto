/* eslint-disable @typescript-eslint/naming-convention */
import {
    AdditionalConfig,
    Provider,
    ProviderFactoryFunctions,
    ProviderImplConfig,
    SecurityLevel
} from "@nmshd/rs-crypto-types";

import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { CryptoHashAlgorithm } from "../hash/CryptoHash";
import { CryptoSignatureAlgorithm } from "../signature/CryptoSignatureAlgorithm";
import {
    CryptoLayerProviderIdentifier,
    KeyMetadata,
    ProviderInitConfig,
    ProviderInitConfigKeyHandle,
    StorageConfig,
    StorageSecurityConfig,
    StorageSecuritySpec
} from "./CryptoLayerConfig";
import { CryptoLayerUtils } from "./CryptoLayerUtils";
import { CryptoEncryptionHandle } from "./encryption/CryptoEncryptionHandle";
import { DeviceBoundKeyHandle } from "./encryption/DeviceBoundKeyHandle";
import { CryptoSignaturesHandle } from "./signature/CryptoSignaturesHandle";
import { DeviceBoundKeyPairHandle } from "./signature/DeviceBoundKeyPairHandle";

const SOFTWARE_PROVIDER_NAME = "SoftwareProvider";
const ANDROID_PROVIDER_NAME = "ANDROID_PROVIDER";
const ANDROID_HARDWARE_PROVIDER_NAME = "ANDROID_PROVIDER_SECURE_ELEMENT";
const APPLE_SECURE_ENCLAVE_PROVIDER_NAME = "APPLE_SECURE_ENCLAVE";
// const WINDOWS_PROVIDER_NAME = "";
// const LINUX_PROVIDER_NAME = "Linux_Provider";

const DEFAULT_STORAGE_SECURITY_CONFIG: StorageSecurityConfig[] = [
    {
        name: ANDROID_HARDWARE_PROVIDER_NAME,
        signature: {
            type: "asymmetric",
            asymmetricKeyAlgorithm: CryptoSignatureAlgorithm.RSA_2048,
            encryptionAlgorithm: undefined,
            hashingAlgorithm: CryptoHashAlgorithm.SHA256
        },
        encryption: {
            type: "symmetric",
            encryptionAlgorithm: CryptoEncryptionAlgorithm.AES256_CBC,
            hashingAlgorithm: CryptoHashAlgorithm.SHA256
        }
    },
    {
        name: ANDROID_PROVIDER_NAME,
        signature: {
            type: "asymmetric",
            asymmetricKeyAlgorithm: CryptoSignatureAlgorithm.RSA_2048,
            encryptionAlgorithm: undefined,
            hashingAlgorithm: CryptoHashAlgorithm.SHA256
        },
        encryption: {
            type: "symmetric",
            encryptionAlgorithm: CryptoEncryptionAlgorithm.AES256_CBC,
            hashingAlgorithm: CryptoHashAlgorithm.SHA256
        }
    },
    {
        name: APPLE_SECURE_ENCLAVE_PROVIDER_NAME,
        signature: {
            type: "asymmetric",
            asymmetricKeyAlgorithm: CryptoSignatureAlgorithm.ECDSA_P256,
            encryptionAlgorithm: undefined,
            hashingAlgorithm: CryptoHashAlgorithm.SHA256
        },
        encryption: {
            type: "asymmetric",
            asymmetricKeyAlgorithm: CryptoSignatureAlgorithm.ECDSA_P256,
            encryptionAlgorithm: CryptoEncryptionAlgorithm.AES256_GCM,
            hashingAlgorithm: CryptoHashAlgorithm.SHA256
        }
    }
];

const PROVIDERS: Map<SecurityLevel, Provider> = new Map();
const PROVIDERS_BY_NAME: Map<string, Provider> = new Map();

async function updateProvidersByNameMap() {
    PROVIDERS_BY_NAME.clear();
    for (const provider of PROVIDERS.values()) {
        const name = await provider.providerName();

        if (PROVIDERS_BY_NAME.has(name)) {
            throw new CryptoError(
                CryptoErrorCode.CalProvidersAlreadyInitialized,
                `Provider '${name}' has already been initialized. Due to scope issues with storage scope this provider cannot be initialized again.`
            ).setContext(updateProvidersByNameMap);
        }

        PROVIDERS_BY_NAME.set(name, provider);
    }
}

async function loadProviderFromName(
    providerName: string,
    providerImplConfig: ProviderImplConfig,
    factoryFunctions: ProviderFactoryFunctions
): Promise<void> {
    const provider = await factoryFunctions.createProviderFromName(providerName, providerImplConfig);

    if (provider === undefined) {
        throw new CryptoError(
            CryptoErrorCode.CalLoadingProvider,
            `Failed initializing provider: '${providerName}'`
        ).setContext(loadProviderFromName);
    }

    const capabilities = await provider.getCapabilities();

    if (capabilities === undefined) {
        throw new CryptoError(
            CryptoErrorCode.CalLoadingProvider,
            `Failed getting capabilities of provider: '${providerName}'`
        ).setContext(loadProviderFromName);
    }

    const securityLevel = capabilities.min_security_level;

    if (PROVIDERS.has(securityLevel)) {
        throw new CryptoError(
            CryptoErrorCode.CalProvidersAlreadyInitialized,
            `Only one provider of a security level can be initialized at a time. Provider for security level '${securityLevel}' has already been loaded.`
        ).setContext(loadProviderFromName);
    }

    PROVIDERS.set(securityLevel, provider);
}

async function additionalConfigFromProviderToBeInitializedConfig(
    providerConfig: ProviderInitConfig
): Promise<AdditionalConfig[]> {
    const additionalConfig = [];

    if (providerConfig.masterEncryptionKeyHandle) {
        const handle = await providerConfig.masterEncryptionKeyHandle.load();
        if (providerConfig.masterEncryptionKeyHandle.type === "symmetric") {
            additionalConfig.push({
                StorageConfigSymmetricEncryption: handle
            });
        } else {
            additionalConfig.push({
                StorageConfigAsymmetricEncryption: handle
            });
        }
    }

    if (providerConfig.masterSignatureKeyHandle) {
        const handle = await providerConfig.masterSignatureKeyHandle.load();
        if (providerConfig.masterSignatureKeyHandle.type === "symmetric") {
            additionalConfig.push({
                StorageConfigHMAC: handle
            });
        } else {
            additionalConfig.push({
                StorageConfigDSA: handle
            });
        }
    }

    return additionalConfig;
}

export async function loadProviderFromConfig(
    providerConfig: ProviderInitConfig,
    storageConfig: StorageConfig,
    factoryFunctions: ProviderFactoryFunctions
): Promise<void> {
    if (providerConfig.dependentProvider !== undefined) {
        await loadProviderFromConfig(providerConfig.dependentProvider, storageConfig, factoryFunctions);
    }

    const implConfig: ProviderImplConfig = {
        additional_config: [storageConfig]
    };

    implConfig.additional_config.push(...(await additionalConfigFromProviderToBeInitializedConfig(providerConfig)));

    await loadProviderFromName(providerConfig.providerName, implConfig, factoryFunctions);

    await updateProvidersByNameMap();
}

async function initializeNewFallbackSoftwareProvider(
    softwareProviderName: string,
    storageConfig: StorageConfig,
    factoryFunctions: ProviderFactoryFunctions
): Promise<ProviderInitConfig> {
    const providerToBeInitializedConfig = ProviderInitConfig.from({
        providerName: softwareProviderName
    });

    await loadProviderFromConfig(providerToBeInitializedConfig, storageConfig, factoryFunctions);

    return providerToBeInitializedConfig;
}

async function keyHandleFromStorageSecuritySpec(
    spec: StorageSecuritySpec
): Promise<DeviceBoundKeyHandle | DeviceBoundKeyPairHandle> {
    if (spec.type === "symmetric") {
        return await CryptoEncryptionHandle.generateDeviceBoundKeyHandle(
            { securityLevel: "Hardware" },
            spec.encryptionAlgorithm,
            spec.hashingAlgorithm
        );
    }
    return await CryptoSignaturesHandle.generateDeviceBoundKeyPairHandle(
        { securityLevel: "Hardware" },
        spec.asymmetricKeyAlgorithm,
        spec.encryptionAlgorithm,
        spec.hashingAlgorithm
    );
}

async function initializeNewHybridProvider(
    hwProviderName: string,
    storageConfig: StorageConfig,
    storageSecurityConfig: StorageSecurityConfig,
    factoryFunctions: ProviderFactoryFunctions
): Promise<ProviderInitConfig> {
    const hwProviderToBeInitialized = ProviderInitConfig.from({
        providerName: hwProviderName
    });

    await loadProviderFromConfig(hwProviderToBeInitialized, storageConfig, factoryFunctions);

    const [encryptionKeyHandle, signatureKeyHandle] = await Promise.all([
        keyHandleFromStorageSecuritySpec(storageSecurityConfig.encryption),
        keyHandleFromStorageSecuritySpec(storageSecurityConfig.signature)
    ]);

    const swProviderToBeInitialized = ProviderInitConfig.from({
        providerName: SOFTWARE_PROVIDER_NAME,
        masterSignatureKeyHandle: ProviderInitConfigKeyHandle.encode(signatureKeyHandle),
        masterEncryptionKeyHandle: ProviderInitConfigKeyHandle.encode(encryptionKeyHandle)
    });

    await loadProviderFromConfig(swProviderToBeInitialized, storageConfig, factoryFunctions);

    swProviderToBeInitialized.dependentProvider = hwProviderToBeInitialized;

    return swProviderToBeInitialized;
}

function storageSecurityForProviderName(
    providerName: string,
    storageSecurityConfig?: StorageSecurityConfig[]
): StorageSecurityConfig | undefined {
    return (
        storageSecurityConfig?.find((config) => config.name === providerName) ??
        DEFAULT_STORAGE_SECURITY_CONFIG.find((config) => config.name === providerName)
    );
}

export async function initializeNewProviders(
    storageConfig: StorageConfig,
    factoryFunctions: ProviderFactoryFunctions,
    storageSecurityConfig?: StorageSecurityConfig[]
): Promise<ProviderInitConfig | undefined> {
    const basicProviderImplConfig: ProviderImplConfig = {
        additional_config: [storageConfig]
    };
    const providerNamesAndCaps = await factoryFunctions.getProviderCapabilities(basicProviderImplConfig);
    const hardwareProviderNamesAndCaps = providerNamesAndCaps
        .filter(([, cap]) => cap.min_security_level === "Hardware")
        .filter(([name]) => storageSecurityForProviderName(name, storageSecurityConfig));

    const softwareProviderNamesAndCaps = providerNamesAndCaps.filter(
        ([, cap]) => cap.min_security_level === "Software"
    );

    if (hardwareProviderNamesAndCaps.length === 0) {
        if (softwareProviderNamesAndCaps.length === 0) {
            return undefined;
        }

        const nonFallbackSoftwareProviders = softwareProviderNamesAndCaps.filter(
            ([name]) => name !== SOFTWARE_PROVIDER_NAME
        );
        if (nonFallbackSoftwareProviders.length !== 0) {
            return await initializeNewFallbackSoftwareProvider(
                nonFallbackSoftwareProviders[0][0],
                storageConfig,
                factoryFunctions
            );
        }
        return await initializeNewFallbackSoftwareProvider(SOFTWARE_PROVIDER_NAME, storageConfig, factoryFunctions);
    }

    const hwProviderName = hardwareProviderNamesAndCaps[0][0];
    const hwStorageSecurityConfig = storageSecurityForProviderName(hwProviderName, storageSecurityConfig);

    if (hwStorageSecurityConfig === undefined) {
        return undefined;
    }

    return await initializeNewHybridProvider(hwProviderName, storageConfig, hwStorageSecurityConfig, factoryFunctions);
}

/**
 * Returns an initialized provider with the given provider identifier if possible,
 * otherwise throws {@link CryptoError} with {@link CryptoErrorCode.CalThisProviderNotInitialized}.
 *
 * Providers need to be initialized via the {@link initCryptoLayerProviders} function,
 * else throws {@link CryptoError} with  {@link CryptoErrorCode.CalProvidersNotInitialized}.
 */
export function getProvider(identifier: CryptoLayerProviderIdentifier): Provider {
    if (PROVIDERS.size === 0) {
        throw new CryptoError(
            CryptoErrorCode.CalProvidersNotInitialized,
            "Failed to get providers as providers are not initialized."
        ).setContext(getProvider);
    }

    let provider: Provider | undefined;

    if ("securityLevel" in identifier) {
        provider = PROVIDERS.get(identifier.securityLevel);
    }
    if ("providerName" in identifier) {
        provider = PROVIDERS_BY_NAME.get(identifier.providerName);
    }

    if (provider === undefined) {
        throw new CryptoError(
            CryptoErrorCode.CalThisProviderNotInitialized,
            `Failed finding provider with identifier ${JSON.stringify(identifier)}`
        ).setContext(getProvider);
    }
    return provider;
}

export function hasProviderForSecurityLevel(securityLevel: SecurityLevel): boolean {
    if (PROVIDERS.size === 0) {
        throw new CryptoError(
            CryptoErrorCode.CalProvidersNotInitialized,
            "Failed to get providers as providers are not initialized."
        ).setContext(hasProviderForSecurityLevel);
    }

    return PROVIDERS.has(securityLevel);
}

export function providersInitialized(): boolean {
    if (PROVIDERS.size !== PROVIDERS_BY_NAME.size) {
        throw new CryptoError(
            CryptoErrorCode.CalLoadingProvider,
            `The maps providers by name and providers by security level are out of sync. (${PROVIDERS_BY_NAME.size} != ${PROVIDERS.size})`
        ).setContext(providersInitialized);
    }

    return PROVIDERS.size !== 0;
}

export function clearProviders(): void {
    PROVIDERS.clear();
    PROVIDERS_BY_NAME.clear();
}

export async function keyCountOfProvider(providerIdent: CryptoLayerProviderIdentifier): Promise<number> {
    const provider = getProvider(providerIdent);

    return (await provider.getAllKeys()).length;
}

export async function keysOfProvider(providerIdent: CryptoLayerProviderIdentifier): Promise<KeyMetadata[]> {
    const provider = getProvider(providerIdent);
    const keys = await provider.getAllKeys();

    return keys.map(([id, spec]) => {
        if ("KeySpec" in spec) {
            return {
                id: id,
                type: "symmetric",
                encryptionAlgorithm: CryptoLayerUtils.cryptoEncryptionAlgorithmFromCipher(spec.KeySpec.cipher),
                hashAlgorithm: CryptoLayerUtils.cryptoHashAlgorithmFromCryptoHash(spec.KeySpec.signing_hash),
                deviceBound: spec.KeySpec.non_exportable,
                ephemeral: spec.KeySpec.ephemeral
            };
        }

        return {
            id: id,
            type: "asymmetric",
            encryptionAlgorithm: spec.KeyPairSpec.cipher
                ? CryptoLayerUtils.cryptoEncryptionAlgorithmFromCipher(spec.KeyPairSpec.cipher)
                : undefined,
            asymmetricKeyAlgorithm: CryptoLayerUtils.cryptoSignatureAlgorithmFromAsymmetricKeySpec(
                spec.KeyPairSpec.asym_spec
            ),
            hashAlgorithm: CryptoLayerUtils.cryptoHashAlgorithmFromCryptoHash(spec.KeyPairSpec.signing_hash),
            deviceBound: spec.KeyPairSpec.non_exportable,
            ephemeral: spec.KeyPairSpec.ephemeral
        };
    });
}
