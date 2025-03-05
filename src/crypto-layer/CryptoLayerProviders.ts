/* eslint-disable @typescript-eslint/naming-convention */
import {
    Provider,
    ProviderConfig,
    ProviderFactoryFunctions,
    ProviderImplConfig,
    SecurityLevel
} from "@nmshd/rs-crypto-types";

import { defaults } from "lodash";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoLayerConfig, CryptoLayerProviderFilter } from "./CryptoLayerConfig";

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
        const caps = await provider.getCapabilities();
        if (!caps) {
            throw new CryptoError(
                CryptoErrorCode.CalFailedLoadingProvider,
                `Failed fetching capabilities or security levels of provider ${providerName}`
            );
        }
        if (caps.max_security_level !== caps.min_security_level) {
            throw new CryptoError(
                CryptoErrorCode.CalFailedLoadingProvider,
                `Minimum and maximum security levels of provider ${providerName} must be the same.`
            );
        }
        const securityLevel = caps.min_security_level;

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
 * If a `SecurityLevel` is given, the default provider config (`DEFAULT_PROVIDER_CONFIG`) will be used to fill in the rest for the selection.
 */
async function createProviderFromProviderFilter(
    providerToBeInitialized: CryptoLayerProviderFilter,
    factoryFunctions: ProviderFactoryFunctions,
    providerImplConfig: ProviderImplConfig
): Promise<Provider | undefined> {
    if ("providerName" in providerToBeInitialized) {
        return await factoryFunctions.createProviderFromName(providerToBeInitialized.providerName, providerImplConfig);
    }
    if ("securityLevel" in providerToBeInitialized) {
        const providerConfig: ProviderConfig = defaults(
            {
                max_security_level: providerToBeInitialized.securityLevel,
                min_security_level: providerToBeInitialized.securityLevel
            },
            DEFAULT_PROVIDER_CONFIG
        );
        return await factoryFunctions.createProvider(providerConfig, providerImplConfig);
    }
    if ("providerConfig" in providerToBeInitialized) {
        return await factoryFunctions.createProvider(providerToBeInitialized.providerConfig, providerImplConfig);
    }

    throw new CryptoError(CryptoErrorCode.WrongParameters);
}

/**
 * Intializes global providers with the given configuration.
 *
 * This enables the crypto layer functionality.
 *
 * @param config Configuration to initialize providers. At least one software provider should be initialized.
 */
export async function initCryptoLayerProviders(config: CryptoLayerConfig): Promise<void> {
    if (PROVIDERS_BY_NAME || PROVIDERS_BY_SECURITY) {
        return;
    }

    const providerImplConfig: ProviderImplConfig = { additional_config: [config.keyMetadataStoreConfig] };
    if (config.keyMetadataStoreAuth) {
        providerImplConfig.additional_config.push(config.keyMetadataStoreAuth);
    }

    const providers: Map<string, Provider> = new Map();

    for (const providerFilter of config.providersToBeInitialized) {
        const provider = await createProviderFromProviderFilter(
            providerFilter,
            config.factoryFunctions,
            providerImplConfig
        );

        if (!provider) {
            throw new CryptoError(CryptoErrorCode.CalFailedLoadingProvider, `Failed loading provider.`);
        }

        providers.set(await provider.providerName(), provider);
    }

    PROVIDERS_BY_NAME = providers;
    PROVIDERS_BY_SECURITY = await providerBySecurityMapFromProviderByNameMap(PROVIDERS_BY_NAME);
}

export type ProviderIdentifier = Exclude<CryptoLayerProviderFilter, { providerConfig: any }>;

/**
 * Returns an initialized provider with the given name or security level if possible.
 *
 * Returns `undefined` if providers are not initialized or provider asked for was not initialized by `initCryptoLayerProviders`.
 */
export function getProvider(identifier: ProviderIdentifier): Provider | undefined {
    if (!PROVIDERS_BY_NAME || !PROVIDERS_BY_SECURITY) {
        return undefined;
    }

    if ("providerName" in identifier) {
        return PROVIDERS_BY_NAME.get(identifier.providerName);
    }
    if ("securityLevel" in identifier) {
        return PROVIDERS_BY_SECURITY.get(identifier.securityLevel)?.[0];
    }

    throw new CryptoError(CryptoErrorCode.WrongParameters);
}

export function getProviderOrThrow(identifier: ProviderIdentifier): Provider {
    const provider = getProvider(identifier);
    if (!provider) {
        throw new CryptoError(
            CryptoErrorCode.WrongParameters,
            `Failed finding provider with name or security level ${identifier}`
        );
    }
    return provider;
}
