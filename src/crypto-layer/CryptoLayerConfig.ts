import { serialize, type, validate } from "@js-soft/ts-serval";
import { AdditionalConfig, SecurityLevel } from "@nmshd/rs-crypto-types";
import { CryptoSerializableAsync } from "../CryptoSerializable";
import { CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { CryptoHashAlgorithm } from "../hash/CryptoHash";
import { CryptoSignatureAlgorithm } from "../signature/CryptoSignatureAlgorithm";
import { DeviceBoundKeyHandle } from "./encryption/DeviceBoundKeyHandle";
import { DeviceBoundKeyPairHandle } from "./signature/DeviceBoundKeyPairHandle";

@type("ProviderInitConfig")
export class ProviderInitConfig extends CryptoSerializableAsync {
    @validate()
    @serialize()
    public providerName: string;

    @validate({ nullable: true })
    @serialize({
        unionTypes: [DeviceBoundKeyHandle, DeviceBoundKeyPairHandle]
    })
    public masterEncryptionKeyHandle?: DeviceBoundKeyHandle | DeviceBoundKeyPairHandle;

    @validate({ nullable: true })
    @serialize({
        unionTypes: [DeviceBoundKeyHandle, DeviceBoundKeyPairHandle]
    })
    public masterSignatureKeyHandle?: DeviceBoundKeyHandle | DeviceBoundKeyPairHandle;

    @validate({ nullable: true })
    @serialize()
    public dependentProvider?: ProviderInitConfig;

    public static new(value: {
        providerName: string;
        masterEncryptionKeyHandle?: DeviceBoundKeyHandle | DeviceBoundKeyPairHandle;
        masterSignatureKeyHandle?: DeviceBoundKeyHandle | DeviceBoundKeyPairHandle;
        dependentProvider?: ProviderInitConfig;
    }): ProviderInitConfig {
        const instance = new ProviderInitConfig();
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
