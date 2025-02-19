import { type } from "@js-soft/ts-serval";
import { KeyPairHandle, KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CryptoAsymmetricKeyHandle } from "./CryptoAsymmetricKeyHandle";

export interface ICryptoPrivateKeyHandle {
    keyPairHandle: KeyPairHandle;
    spec: KeyPairSpec;
}

export interface ICryptoPrivateKeyHandleStatic {
    new (): ICryptoPrivateKeyHandle;
    fromNativeKey(key: any, spec: KeyPairSpec): Promise<ICryptoPrivateKeyHandle>;
}

@type("CryptoPrivateKeyHandle")
export class CryptoPrivateKeyHandle extends CryptoAsymmetricKeyHandle implements ICryptoPrivateKeyHandle {}
