import { Serializable, serialize, type, validate } from "@js-soft/ts-serval";
import { AdditionalConfig } from "@nmshd/rs-crypto-types";
import { DeviceBoundKeyHandle } from "./encryption/DeviceBoundKeyHandle";

@type("CryptoLayerProviderToBeInitialized")
export class CryptoLayerProviderToBeInitialized {
    @validate({ nullable: true })
    @serialize()
    public masterEncryptionKeyHandle: DeviceBoundKeyHandle | undefined;

    @validate({ nullable: true })
    @serialize()
    public masterSignatureKeyHandle: DeviceBoundKeyHandle | undefined;

    @validate()
    @serialize()
    public storageMethod: AdditionalConfig;
}

/**
 * A scope to fix a provider to its key metadata storage configuration.
 *
 * Providers created with different encryption and signature keys are not able to access each others key metadata
 * and thus unable to load each others keys.
 * The same applies in regards to the method of storage of said key metadata.
 *
 * `storageStorageScope` is a custom value that should be used as reference to the storage backend used for storing key metadata.
 */
@type("CryptoLayerProviderIdentifier")
export class CryptoLayerProviderIdentifier extends Serializable {
    @validate()
    @serialize()
    public providerName: string;

    @validate({ nullable: true })
    @serialize()
    public storageSignatureKeyId: string | undefined;

    @validate({ nullable: true })
    @serialize()
    public storageEncryptionKeyId: string | undefined;

    @validate({ nullable: true })
    @serialize()
    public storageStorageScope: string | undefined;

    public equals(other: CryptoLayerProviderIdentifier): boolean {
        return (
            this.providerName === other.providerName &&
            this.storageEncryptionKeyId === other.storageEncryptionKeyId &&
            this.storageSignatureKeyId === other.storageSignatureKeyId &&
            this.storageStorageScope === other.storageStorageScope
        );
    }
}
