/* eslint-disable @typescript-eslint/naming-convention */
import { AdditionalConfig, ProviderConfig, ProviderFactoryFunctions, SecurityLevel } from "@nmshd/rs-crypto-types";

/**
 * Interface holding functions for listing and creating providers and configuration for initializing the key meta data store.
 *
 * @property factoryFunctions - Functions that list providers or create providers.
 * @property keyMetadataStoreConfig - Configuration needed for saving key metadata.
 * @property keyMetadataStoreAuth - ~~Optional~~ configuration for authenticating key metadata.
 * @property providersToBeInitialized - Array of providers to initalize.
 */
export interface CryptoLayerConfig {
    factoryFunctions: ProviderFactoryFunctions;
    keyMetadataStoreConfig: Extract<AdditionalConfig, { KVStoreConfig: any } | { FileStoreConfig: any }>;
    keyMetadataStoreAuth?: Extract<
        AdditionalConfig,
        { StorageConfigHMAC: any } | { StorageConfigDSA: any } | { StorageConfigPass: any }
    >;
    providersToBeInitialized: CryptoLayerProviderFilter[];
}

/**
 * Reference to a specific provider, if a name is supplied, or any provider that fullfills the other requirements.
 */
export type CryptoLayerProviderFilter =
    | {
          providerName: string;
      }
    | {
          securityLevel: SecurityLevel;
      }
    | {
          providerConfig: ProviderConfig;
      };
