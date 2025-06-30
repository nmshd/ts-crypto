import { Serializable, serialize, type, validate } from "@js-soft/ts-serval";
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


/**
 * A scope to fix a provider to its key metadata storage configuration.
 * 
 * Providers created with different encryption and signature keys are not able to access each others key metadata
 * and thus unable to load each others keys.
 * The same applies in regards to the method of storage of said key metadata.
 * 
 * `storageStorageScope` is a custom value that should be used as reference to the storage backend used for storing key metadata.
 */
@type("CryptoLayerProviderScope")
export class CryptoLayerProviderScope extends Serializable {
    @validate()
    @serialize()
    public providerName: string
    
    @validate({nullable: true})
    @serialize()
    public storageSignatureKeyId: string | undefined

    @validate({nullable: true})
    @serialize()
    public storageEncryptionKeyId: string | undefined

    @validate({nullable: true})
    @serialize()
    public storageStorageScope: string | undefined
}
