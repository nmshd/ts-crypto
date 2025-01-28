import { Serializable, serialize, type, validate } from "@js-soft/ts-serval";
import { assert } from "console";
import { KeyPairHandle, Provider } from "crypto-layer-ts-types";

@type("CryptoLayerKeyPair")
export class CryptoLayerKeyPair extends Serializable {
    @validate()
    @serialize()
    public readonly id: string;
    
    @validate()
    @serialize()
    public readonly providerName: string;

    public provider?: Provider;
    public keyPairHandle?: KeyPairHandle;

    constructor(provider: Provider, keyPairHandle: KeyPairHandle) {
        super();
        this.provider = provider;
        this.keyPairHandle = keyPairHandle;
        this.id = keyPairHandle.id();
        this.providerName = provider.providerName();
    }

    public init(provider: Provider): void {
        assert(provider.providerName() == this.providerName);
        this.provider = provider;
        this.keyPairHandle = provider.loadKeyPair(this.id);
    }
}