/* eslint-disable @typescript-eslint/naming-convention */
import {
    Provider,
    ProviderConfig,
    ProviderFactoryFunctions,
    ProviderImplConfig,
    SecurityLevel
} from "@nmshd/rs-crypto-types";

import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoLayerConfig, CryptoLayerProviderToBeInitialized } from "./CryptoLayerConfig";

let PROVIDERS_BY_SECURITY: Map<SecurityLevel, Provider[]> | undefined = undefined;
let PROVIDERS_BY_NAME: Map<string, Provider> | undefined = undefined;

const DEFAULT_PROVIDER_CONFIG: ProviderConfig = {
    max_security_level: "Hardware",
    min_security_level: "Software",
    supported_asym_spec: ["P256", "Curve25519"],
    supported_ciphers: ["AesCbc256", "AesGcm256"],
    supported_hashes: ["Sha2_256", "Sha2_512"]
};

async function providerBySecurityMapFromProviderByNameMap(
    providersByName: Map<string, Provider>
): Promise<Map<SecurityLevel, Provider[]>> {
    const providersBySecurity = new Map<SecurityLevel, Provider[]>();
    for (const [providerName, provider] of providersByName) {
        const capabilities = await provider.getCapabilities();
        if (!capabilities) {
            throw new CryptoError(
                CryptoErrorCode.CalLoadingProvider,
                `Failed fetching capabilities or security levels of provider ${providerName}`
            ).setContext(providerBySecurityMapFromProviderByNameMap);
        }
        if (capabilities.max_security_level !== capabilities.min_security_level) {
            throw new CryptoError(
                CryptoErrorCode.CalLoadingProvider,
                `Minimum and maximum security levels of provider ${providerName} must be the same.`
            ).setContext(providerBySecurityMapFromProviderByNameMap);
        }
        const securityLevel = capabilities.min_security_level;

        if (!providersBySecurity.has(securityLevel)) {
            providersBySecurity.set(securityLevel, []);
        }

        providersBySecurity.get(securityLevel)!.push(provider);
    }
    return providersBySecurity;
}

/**
 * Creates a provider if possible with the given provider filter. This means, that the provider created must adhere to the filter.
 *
 * If a `SecurityLevel` is given, the default provider config {@link DEFAULT_PROVIDER_CONFIG} will be used to fill in the rest for the selection.
 */
async function createProviderFromProviderFilter(
    providerToBeInitialized: CryptoLayerProviderToBeInitialized,
    factoryFunctions: ProviderFactoryFunctions,
    providerImplConfig: ProviderImplConfig
): Promise<Provider | undefined> {
    if ("providerName" in providerToBeInitialized) {
        return await factoryFunctions.createProviderFromName(providerToBeInitialized.providerName, providerImplConfig);
    }
    if ("securityLevel" in providerToBeInitialized) {
        const providerConfig: ProviderConfig = {
            ...DEFAULT_PROVIDER_CONFIG,
            max_security_level: providerToBeInitialized.securityLevel,
            min_security_level: providerToBeInitialized.securityLevel
        };
        return await factoryFunctions.createProvider(providerConfig, providerImplConfig);
    }
    if ("providerConfig" in providerToBeInitialized) {
        return await factoryFunctions.createProvider(providerToBeInitialized.providerConfig, providerImplConfig);
    }

    throw new CryptoError(
        CryptoErrorCode.WrongParameters,
        `No available provider matches the given requirements: ${JSON.stringify(providerToBeInitialized)}`
    ).setContext(createProviderFromProviderFilter);
}

/**
 * Initializes a list of global providers with the given configuration.
 */
export async function initCryptoLayerProviders(config: CryptoLayerConfig): Promise<void> {
    if (PROVIDERS_BY_NAME !== undefined && PROVIDERS_BY_SECURITY !== undefined) {
        throw new CryptoError(
            CryptoErrorCode.CalProvidersAlreadyInitialized,
            "Providers cannot be initialized again."
        ).setContext(initCryptoLayerProviders);
    }

    const providers: Map<string, Provider> = new Map();

    for (const [providerToBeInitialized, providerImplConfig] of config.providersToBeInitialized) {
        const provider = await createProviderFromProviderFilter(
            providerToBeInitialized,
            config.factoryFunctions,
            providerImplConfig
        );

        if (provider === undefined) {
            throw new CryptoError(
                CryptoErrorCode.CalLoadingProvider,
                `Failed loading provider with given requirements: ${JSON.stringify(providerToBeInitialized)}`
            ).setContext(initCryptoLayerProviders);
        }

        providers.set(await provider.providerName(), provider);
    }

    PROVIDERS_BY_NAME = providers;
    PROVIDERS_BY_SECURITY = await providerBySecurityMapFromProviderByNameMap(PROVIDERS_BY_NAME);
}

export type ProviderIdentifier = Exclude<CryptoLayerProviderToBeInitialized, { providerConfig: any }>;

/**
 * Returns an initialized provider with the given name or security level if possible,
 * otherwise throws {@link CryptoError} with {@link CryptoErrorCode.CalThisProviderNotInitialized}.
 *
 * Providers need to be initialized via the {@link initCryptoLayerProviders} function,
 * else throws {@link CryptoError} with  {@link CryptoErrorCode.CalProvidersNotInitialized}.
 */
export function getProvider(identifier: ProviderIdentifier): Provider {
    if (PROVIDERS_BY_NAME === undefined || PROVIDERS_BY_SECURITY === undefined) {
        throw new CryptoError(
            CryptoErrorCode.CalProvidersNotInitialized,
            "Failed to get providers as providers are not initialized."
        ).setContext(getProvider);
    }

    let provider: Provider | undefined;

    if ("providerName" in identifier) {
        provider = PROVIDERS_BY_NAME.get(identifier.providerName);
    } else if ("securityLevel" in identifier) {
        provider = PROVIDERS_BY_SECURITY.get(identifier.securityLevel)?.[0];
    } else {
        throw new CryptoError(
            CryptoErrorCode.WrongParameters,
            "Provider identifier was not able to be parsed while trying to get a provider."
        ).setContext(getProvider);
    }

    if (provider === undefined) {
        throw new CryptoError(
            CryptoErrorCode.CalThisProviderNotInitialized,
            `Failed finding provider with name or security level ${identifier}`
        ).setContext(getProvider);
    }
    return provider;
}

export function hasProviderForSecurityLevel(securityLevel: SecurityLevel): boolean {
    if (PROVIDERS_BY_SECURITY === undefined) {
        throw new CryptoError(
            CryptoErrorCode.CalProvidersNotInitialized,
            "Failed to get providers as providers are not initialized."
        ).setContext(hasProviderForSecurityLevel);
    }

    const providers = PROVIDERS_BY_SECURITY.get(securityLevel);
    return providers !== undefined && providers.length > 0;
}
