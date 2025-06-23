import { ProviderConfig, ProviderFactoryFunctions, ProviderImplConfig, SecurityLevel } from "@nmshd/rs-crypto-types";

/**
 * Interface holding functions for listing and creating providers and configuration for initializing the key meta data store.
 */
export interface CryptoLayerConfig {
    factoryFunctions: ProviderFactoryFunctions;
    providersToBeInitialized: [CryptoLayerProviderToBeInitialized, ProviderImplConfig][];
}

/**
 * Reference to a specific provider, if a name is supplied, or any provider that fulfills the other requirements.
 */
export type CryptoLayerProviderToBeInitialized =
    | {
          providerName: string;
      }
    | {
          securityLevel: SecurityLevel;
      }
    | {
          providerConfig: ProviderConfig;
      };
