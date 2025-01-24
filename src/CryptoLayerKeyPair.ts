import { Serializable, serialize, type, validate } from "@js-soft/ts-serval";
import { KeyPairHandle, Provider } from "crypto-layer-ts-types";

@type("CryptoLayerKeyPair")
export class CryptoLayerKeyPair extends Serializable {
    @validate()
    @serialize()
    public readonly id: string;
    
    @validate()
    @serialize()
    public readonly providerName: string;

    public readonly provider?: Provider;
    public readonly keyPairHandle?: KeyPairHandle;

    constructor(provider: Provider, keyPairHandle: KeyPairHandle) {
        super();
        this.provider = provider;
        this.keyPairHandle = keyPairHandle;
        this.id = keyPairHandle.id();
        this.providerName = provider.providerName();
    }
}