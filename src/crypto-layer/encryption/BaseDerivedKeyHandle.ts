// filepath: m:\DEV\WorkProjects\nmshd2\ts-crypto\src\crypto-layer\encryption\DerivedBaseKeyHandle.ts
import { KeyHandle, Provider } from "@nmshd/rs-crypto-types";
import { CryptoEncryptionAlgorithm } from "../../encryption/CryptoEncryption"; // Path relative to src/crypto-layer/encryption/
import { CryptoHashAlgorithm } from "../../hash/CryptoHash"; // Assuming 'src/' is a root path or alias
import { CryptoLayerUtils } from "../CryptoLayerUtils"; // Path relative to src/crypto-layer/encryption/

/**
 * Variant of {@link BaseKeyHandle} without serialization and deserialization.
 */
export abstract class BaseDerivedKeyHandle {
    public id: string;
    public providerName: string;

    public provider: Provider;
    public keyHandle: KeyHandle;

    public async encryptionAndHashAlgorithm(): Promise<[CryptoEncryptionAlgorithm, CryptoHashAlgorithm]> {
        const spec = await this.keyHandle.spec();
        return [
            CryptoLayerUtils.cryptoEncryptionAlgorithmFromCipher(spec.cipher),
            CryptoLayerUtils.cryptoHashAlgorithmFromCryptoHash(spec.signing_hash)
        ];
    }

    public async encryptionAlgorithm(): Promise<CryptoEncryptionAlgorithm> {
        const spec = await this.keyHandle.spec();
        return CryptoLayerUtils.cryptoEncryptionAlgorithmFromCipher(spec.cipher);
    }

    public async hashAlgorithm(): Promise<CryptoHashAlgorithm> {
        const spec = await this.keyHandle.spec();
        return CryptoLayerUtils.cryptoHashAlgorithmFromCryptoHash(spec.signing_hash);
    }
}

export abstract class ImportableBaseDerivedKeyHandle extends BaseDerivedKeyHandle {
    // Phantom marker to make this type incompatible with `BaseDerivedKeyHandle`.
    public readonly _importable = true;
}
