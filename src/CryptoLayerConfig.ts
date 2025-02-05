import { AdditionalConfig, ProviderConfig, ProviderFactoryFunctions, SecurityLevel } from "crypto-layer-ts-types";

/**
 * Type holding functions for listing and creating providers and configuration for initializing the key meta data store.
 *
 * @property factoryFunctions - Functions that list providers or create providers.
 * @property keyMetadataStoreConfig - Configuration needed for saving key metadata.
 * @property keyMetadataStoreAuth - ~~Optional~~ configuration for authenticating key metadata.
 * @property providers - Array of providers to initalize.
 */
export type CryptoLayerConfig = {
    factoryFunctions: ProviderFactoryFunctions;
    keyMetadataStoreConfig: Extract<AdditionalConfig, { KVStoreConfig: any } | { FileStoreConfig: any }>;
    keyMetadataStoreAuth?: Extract<
        AdditionalConfig,
        { StorageConfigHMAC: any } | { StorageConfigDSA: any } | { StorageConfigPass: any }
    >;
    providers: CryptoLayerProviderConfig[];
};

export type CryptoLayerProviderConfig =
    | {
          providerName: string;
      }
    | {
          securityLevel: SecurityLevel;
      }
    | {
          providerConfig: ProviderConfig;
      };
