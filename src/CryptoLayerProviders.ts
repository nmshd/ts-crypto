import { Provider, ProviderConfig, ProviderImplConfig, SecurityLevel } from "crypto-layer-ts-types";

import { defaults } from "lodash";
import { CryptoError } from "./CryptoError";
import { CryptoErrorCode } from "./CryptoErrorCode";
import { CryptoLayerConfig } from "./CryptoLayerConfig";

let PROVIDERS_BY_SECURITY: Map<SecurityLevel, Provider[]> | undefined = undefined;
let PROVIDERS_BY_NAME: Map<string, Provider> | undefined = undefined;

const DEFAULT_PROVIDER_CONFIG: ProviderConfig = {
    max_security_level: "Hardware",
    min_security_level: "Software",
    supported_asym_spec: ["P256", "Curve25519"],
    supported_ciphers: ["AesCbc256", "AesGcm256"],
    supported_hashes: ["Sha2_256", "Sha2_512"]
};

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

    let providerImplConfig: ProviderImplConfig = { additional_config: [config.keyMetadataStoreConfig] };
    if (config.keyMetadataStoreAuth) {
        providerImplConfig.additional_config.push(config.keyMetadataStoreAuth);
    }

    let providers: Map<string, Provider> = new Map();

    for (const providerInitalizationConfig of config.providers) {
        let provider: Provider | undefined;
        if ("providerName" in providerInitalizationConfig) {
            provider = await config.factoryFunctions.createProviderFromName(
                providerInitalizationConfig.providerName,
                providerImplConfig
            );
        } else if ("securityLevel" in providerInitalizationConfig) {
            let providerConfig: ProviderConfig = defaults(
                {
                    max_security_level: providerInitalizationConfig.securityLevel,
                    min_security_level: providerInitalizationConfig.securityLevel
                },
                DEFAULT_PROVIDER_CONFIG
            );
            provider = await config.factoryFunctions.createProvider(providerConfig, providerImplConfig);
        } else if ("providerConfig" in providerInitalizationConfig) {
            provider = await config.factoryFunctions.createProvider(
                providerInitalizationConfig.providerConfig,
                providerImplConfig
            );
        } else {
            throw new CryptoError(CryptoErrorCode.WrongParameters);
        }

        if (!provider) {
            throw new CryptoError(CryptoErrorCode.CalFailedLoadingProvider, `Failed loading provider.`);
        }

        providers.set(await provider.providerName(), provider);
    }

    PROVIDERS_BY_NAME = providers;

    let providers_by_security = new Map();
    for (const [key, value] of providers) {
        let caps = await value.getCapabilities();
        if (!caps?.min_security_level) {
            continue;
        }
        let securityLevel = caps.min_security_level;

        if (!providers_by_security.has(securityLevel)) {
            providers_by_security.set(securityLevel, []);
        }

        providers_by_security.get(securityLevel)!.push(value);
    }

    PROVIDERS_BY_SECURITY = providers_by_security;
}

function isSecurityLevel(value: string): value is SecurityLevel {
    const securityLevels = ["Hardware", "Network", "Software", "Unsafe"];
    return securityLevels.includes(value);
}

/**
 * Returns an initialized provider with the given name or security level if possible.
 *
 * This function is structured in a way that if `initCryptoLayerProviders()` was never called it always returns undefined.
 *
 * @param key Name of a provider or security level.
 * @returns `Provider` with security level or name if providers are initialized (with `initCryptoLayerProviders`).
 *              `undefined` if providers where not initialized or if key is undefined.
 *
 * @throws `CryptoError` with `CryptoErrorCode.WrongParameters` if provider name or security level could not be matched to any provider
 *              if providers have been initialized.
 */
export function getProvider(key: string | SecurityLevel): Provider {
    if (!PROVIDERS_BY_NAME || !PROVIDERS_BY_SECURITY) {
        throw new CryptoError(CryptoErrorCode.CalFailedLoadingProvider);
    }

    let provider = isSecurityLevel(key) ? PROVIDERS_BY_SECURITY.get(key)?.[0] : PROVIDERS_BY_NAME.get(key);

    if (!provider) {
        throw new CryptoError(CryptoErrorCode.WrongParameters, `No such provider with name or security level: ${key}`);
    }

    return provider;
}
