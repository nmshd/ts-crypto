import { Serializable, serialize, type, validate } from "@js-soft/ts-serval";
import { AsymmetricKeySpec, CryptoHash, KeyPairHandle, KeyPairSpec, Provider } from "@nmshd/rs-crypto-types";
import { defaults } from "lodash";
import { CoreBuffer } from "./CoreBuffer";
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

export function asymSpecFromCryptoAlgorithm(
    algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm
): AsymmetricKeySpec {
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

export function cryptoHashFromCryptoHashAlgorithm(algorithm: CryptoHashAlgorithm): CryptoHash {
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

    constructor(id: string, providerName: string, provider?: Provider, keyPairHandle?: KeyPairHandle) {
        super();
        this.provider = provider;
        this.keyPairHandle = keyPairHandle;
        this.id = id;
        this.providerName = providerName;
    }

    /**
     * Creates a new `CryptoLayerKeyPair` object.
     *
     * @param provider Provider which the key pair was created with.
     * @param keyPairHandle Key pair handle holding private and public keys.
     * @returns `CryptoLayerKeyPair` on success.
     */
    public static async new(provider: Provider, keyPairHandle: KeyPairHandle): Promise<CryptoLayerKeyPair> {
        return new CryptoLayerKeyPair(await keyPairHandle.id(), await provider.providerName(), provider, keyPairHandle);
    }

    /**
     * Loads the key with the provider.
     *
     * @param provider Provider which is used to load the key pair and populate `CryptoLayerKeyPair`.
     */
    public async init(provider: Provider): Promise<void> {
        if ((await provider.providerName()) != this.providerName) {
            throw new CryptoError(
                CryptoErrorCode.CalWrongProvider,
                `A key must always be loaded with the provider is was created with! You supplied: ${provider.providerName()}. Expected provider: ${this.providerName}`
            );
        }
        this.provider = provider;
        this.keyPairHandle = await provider.loadKeyPair(this.id);
    }

    /**
     * Constructs a CryptoLayerKeyPair with default key spec from raw private key.
     *
     * @param provider A crypto layer provider that is capable of importing a key pair.
     * @param privateKeyBuffer The raw private key.
     * @param specOverride Override default key pair spec.
     * @returns New CryptoLayerKeyPair with handle to key pair.
     */
    public static async fromPrivateBuffer(
        provider: Provider,
        privateKeyBuffer: CoreBuffer,
        specOverride: Partial<KeyPairSpec>
    ): Promise<CryptoLayerKeyPair> {
        let spec = defaults(specOverride, DEFAULT_KEY_PAIR_SPEC);
        let keyPair = await provider.importKeyPair(spec, new Uint8Array(0), privateKeyBuffer.buffer);
        return CryptoLayerKeyPair.new(provider, keyPair);
    }

    public static async fromPrivateBufferWithAlgorithm(
        provider: Provider,
        privateKeyBuffer: CoreBuffer,
        asymmetricAlgorithm?: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm,
        hashAlgorithm?: CryptoHashAlgorithm
    ): Promise<CryptoLayerKeyPair> {
        let override: Partial<KeyPairSpec> = {
            asym_spec: asymmetricAlgorithm ? asymSpecFromCryptoAlgorithm(asymmetricAlgorithm) : undefined,
            signing_hash: hashAlgorithm ? cryptoHashFromCryptoHashAlgorithm(hashAlgorithm) : undefined
        };
        return this.fromPrivateBuffer(provider, privateKeyBuffer, override);
    }

    /**
     * Constructs a CryptoLayerKeyPair with default key spec from raw public key.
     *
     * @param provider A crypto layer provider that is capable of importing a key pair.
     * @param privateKeyBuffer The raw public key.
     * @param specOverride Override default key pair spec.
     * @returns New CryptoLayerKeyPair with handle to key pair.
     */
    public static async fromPublicBuffer(
        provider: Provider,
        publicKeyBuffer: CoreBuffer,
        specOverride: Partial<KeyPairSpec>
    ): Promise<CryptoLayerKeyPair> {
        let spec = defaults(specOverride, DEFAULT_KEY_PAIR_SPEC);
        let keyPair = await provider.importPublicKey(spec, publicKeyBuffer.buffer);
        return CryptoLayerKeyPair.new(provider, keyPair);
    }

    public static async fromPublicBufferWithAlgorithm(
        provider: Provider,
        privateKeyBuffer: CoreBuffer,
        asymmetricAlgorithm?: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm,
        hashAlgorithm?: CryptoHashAlgorithm
    ): Promise<CryptoLayerKeyPair> {
        let override: Partial<KeyPairSpec> = {
            asym_spec: asymmetricAlgorithm ? asymSpecFromCryptoAlgorithm(asymmetricAlgorithm) : undefined,
            signing_hash: hashAlgorithm ? cryptoHashFromCryptoHashAlgorithm(hashAlgorithm) : undefined
        };
        return this.fromPublicBuffer(provider, privateKeyBuffer, override);
    }
}
