import { serialize, type, validate } from "@js-soft/ts-serval";
import { AdditionalConfig, KeyHandle, KeyPairHandle, SecurityLevel } from "@nmshd/rs-crypto-types";
import { CryptoSerializable } from "../CryptoSerializable";
import { CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { CryptoHashAlgorithm } from "../hash/CryptoHash";
import { CryptoSignatureAlgorithm } from "../signature/CryptoSignatureAlgorithm";
import { getProvider } from "./CryptoLayerProviders";
import { DeviceBoundKeyHandle } from "./encryption/DeviceBoundKeyHandle";
import { DeviceBoundKeyPairHandle } from "./signature/DeviceBoundKeyPairHandle";

type KeyHandleType = "symmetric" | "asymmetric";

interface IProviderInitConfigKeyHandle {
    type: KeyHandleType;
    keyId: string;
    providerName: string;
}

@type("ProviderInitConfigKeyHandle")
export class ProviderInitConfigKeyHandle extends CryptoSerializable {
    @validate()
    @serialize()
    public type: KeyHandleType;

    @validate()
    @serialize()
    public keyId: string;

    @validate()
    @serialize()
    public providerName: string;

    public static from(value: IProviderInitConfigKeyHandle): ProviderInitConfigKeyHandle {
        return ProviderInitConfigKeyHandle.fromAny(value);
    }

    public static encode(handle: DeviceBoundKeyHandle | DeviceBoundKeyPairHandle): ProviderInitConfigKeyHandle {
        return ProviderInitConfigKeyHandle.from({
            type: handle instanceof DeviceBoundKeyHandle ? "symmetric" : "asymmetric",
            keyId: handle.id,
            providerName: handle.providerName
        });
    }

    public async load(): Promise<KeyHandle | KeyPairHandle> {
        const provider = getProvider({ providerName: this.providerName });

        switch (this.type) {
            case "asymmetric":
                return await provider.loadKeyPair(this.keyId);
            case "symmetric":
                return await provider.loadKey(this.keyId);
        }
    }
}

interface IProviderInitConfig {
    providerName: string;
    masterEncryptionKeyHandle?: ProviderInitConfigKeyHandle;
    masterSignatureKeyHandle?: ProviderInitConfigKeyHandle;
    dependentProvider?: ProviderInitConfig;
}

@type("ProviderInitConfig")
export class ProviderInitConfig extends CryptoSerializable {
    @validate()
    @serialize()
    public providerName: string;

    @validate({ nullable: true })
    @serialize()
    public masterEncryptionKeyHandle?: ProviderInitConfigKeyHandle;

    @validate({ nullable: true })
    @serialize()
    public masterSignatureKeyHandle?: ProviderInitConfigKeyHandle;

    @validate({ nullable: true })
    @serialize()
    public dependentProvider?: ProviderInitConfig;

    public static from(value: IProviderInitConfig): ProviderInitConfig {
        return ProviderInitConfig.fromAny(value);
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

export type KeyMetadata =
    | {
          id: string;
          type: "symmetric";
          encryptionAlgorithm: CryptoEncryptionAlgorithm;
          hashAlgorithm: CryptoHashAlgorithm;
          deviceBound: boolean;
          ephemeral: boolean;
      }
    | {
          id: string;
          type: "asymmetric";
          asymmetricKeyAlgorithm: CryptoSignatureAlgorithm;
          encryptionAlgorithm?: CryptoEncryptionAlgorithm;
          hashAlgorithm: CryptoHashAlgorithm;
          deviceBound: boolean;
          ephemeral: boolean;
      };
