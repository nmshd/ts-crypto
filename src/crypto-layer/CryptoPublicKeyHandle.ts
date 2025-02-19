import { type } from "@js-soft/ts-serval";
import { KeyPairHandle, KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CryptoAsymmetricKeyHandle } from "./CryptoAsymmetricKeyHandle";

export interface ICryptoPublicKeyHandle {
    keyPairHandle: KeyPairHandle;
    spec: KeyPairSpec;
}

export interface ICryptoPublicKeyHandleStatic {
    new (): ICryptoPublicKeyHandle;
    fromNativeKey(key: any, spec: KeyPairSpec): Promise<ICryptoPublicKeyHandle>;
}

@type("CryptoPublicKeyHandle")
export class CryptoPublicKeyHandle extends CryptoAsymmetricKeyHandle implements ICryptoPublicKeyHandle {}
