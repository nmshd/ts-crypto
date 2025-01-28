import { Serializable, serialize, type, validate } from "@js-soft/ts-serval";
import { assert } from "console";
import { AsymmetricKeySpec, CryptoHash, KeyPairHandle, KeyPairSpec, Provider } from "crypto-layer-ts-types";
import { CryptoError } from "./CryptoError";
import { CryptoErrorCode } from "./CryptoErrorCode";
import { CryptoExchangeAlgorithm } from "./exchange/CryptoExchange";
import { CryptoHashAlgorithm } from "./hash/CryptoHash";
import { CryptoSignatureAlgorithm } from "./signature/CryptoSignatureAlgorithm";

export const DEFAULT_KEY_PAIR_SPEC: KeyPairSpec = {
    asym_spec: "P256",
    cipher: "AesGcm256",
    signing_hash: "Sha2_512",
    ephemeral: false,
    non_exportable: false
};

export function asymSpecFromCryptoAlgorithm(algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm): AsymmetricKeySpec {
    switch (algorithm) {
        case CryptoExchangeAlgorithm.ECDH_P256:
            return "P256";
        case CryptoExchangeAlgorithm.ECDH_P521:
            return "P521";
        case CryptoExchangeAlgorithm.ECDH_X25519:
            return "Curve25519";
        case CryptoSignatureAlgorithm.ECDSA_P256:
            return "P256";
        case CryptoSignatureAlgorithm.ECDSA_P521:
            return "P521";
        case CryptoSignatureAlgorithm.ECDSA_ED25519:
            return "Curve25519";
    }
}

export function CryptoHashFromCryptoHashAlgorithm(algorithm: CryptoHashAlgorithm): CryptoHash {
    switch (algorithm) {
        case CryptoHashAlgorithm.SHA256:
            return "Sha2_256";
        case CryptoHashAlgorithm.SHA512:
            return "Sha2_512";
        case CryptoHashAlgorithm.BLAKE2B:
            throw new CryptoError(CryptoErrorCode.CalUnsupportedAlgorithm);
    }
}

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