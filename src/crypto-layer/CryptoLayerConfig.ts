import { serialize, type, validate } from "@js-soft/ts-serval";
import { AdditionalConfig, SecurityLevel } from "@nmshd/rs-crypto-types";
import { CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { CryptoHashAlgorithm } from "../hash/CryptoHash";
import { CryptoSignatureAlgorithm } from "../signature/CryptoSignatureAlgorithm";
import { DeviceBoundKeyHandle } from "./encryption/DeviceBoundKeyHandle";
import { DeviceBoundKeyPairHandle } from "./signature/DeviceBoundKeyPairHandle";

@type("CryptoLayerProviderToBeInitialized")
export class CryptoLayerProviderToBeInitialized {
    @validate()
    @serialize()
    public providerName: string;

    @validate({ nullable: true })
    @serialize()
    public masterEncryptionKeyHandle: DeviceBoundKeyHandle | DeviceBoundKeyPairHandle | undefined;

    @validate({ nullable: true })
    @serialize()
    public masterSignatureKeyHandle: DeviceBoundKeyHandle | DeviceBoundKeyPairHandle | undefined;

    @validate({ nullable: true })
    @serialize()
    public dependentProvider: CryptoLayerProviderToBeInitialized | undefined;

    public static new(value: {
        providerName: string;
        masterEncryptionKeyHandle?: DeviceBoundKeyHandle | DeviceBoundKeyPairHandle;
        masterSignatureKeyHandle?: DeviceBoundKeyHandle | DeviceBoundKeyPairHandle;
        dependentProvider?: CryptoLayerProviderToBeInitialized;
    }): CryptoLayerProviderToBeInitialized {
        const instance = new CryptoLayerProviderToBeInitialized();
        instance.providerName = value.providerName;
        instance.masterEncryptionKeyHandle = value.masterEncryptionKeyHandle;
        instance.masterSignatureKeyHandle = value.masterSignatureKeyHandle;
        instance.dependentProvider = value.dependentProvider;
        return instance;
    }
}

// eslint-disable-next-line @typescript-eslint/naming-convention
export type StorageConfig = Extract<AdditionalConfig, { KVStoreConfig: any } | { FileStoreConfig: any }>;

export type CryptoLayerProviderIdentifier =
    | {
          providerName: string;
      }
    | {
          securityLevel: SecurityLevel;
      };

export type StorageSecuritySpec =
    | {
          type: "asymmetric";
          asymmetricKeyAlgorithm: CryptoSignatureAlgorithm;
          encryptionAlgorithm: CryptoEncryptionAlgorithm | undefined;
          hashingAlgorithm: CryptoHashAlgorithm;
      }
    | {
          type: "symmetric";
          encryptionAlgorithm: CryptoEncryptionAlgorithm;
          hashingAlgorithm: CryptoHashAlgorithm;
      };

export interface StorageSecurityConfig {
    name: string;
    signature: StorageSecuritySpec;
    encryption: StorageSecuritySpec;
}
