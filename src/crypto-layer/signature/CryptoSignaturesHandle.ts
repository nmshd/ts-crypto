import { KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CryptoEncryptionAlgorithm } from "../../encryption/CryptoEncryption";
import { CryptoHashAlgorithm } from "../../hash/CryptoHash";
import { CryptoSignatureAlgorithm } from "../../signature/CryptoSignatureAlgorithm";
import { CryptoLayerProviderIdentifier } from "../CryptoLayerConfig";
import { getProvider } from "../CryptoLayerProviders";
import { CryptoLayerUtils } from "../CryptoLayerUtils";
import { DeviceBoundKeyPairHandle } from "./DeviceBoundKeyPairHandle";

export class CryptoSignaturesHandle {
    public static async generateDeviceBoundKeyPairHandle(
        providerIdent: CryptoLayerProviderIdentifier,
        asymmetricKeyAlgorithm: CryptoSignatureAlgorithm,
        encryptionAlgorithm: CryptoEncryptionAlgorithm | undefined,
        hashAlgorithm: CryptoHashAlgorithm
    ): Promise<DeviceBoundKeyPairHandle> {
        const deviceBoundSpec: KeyPairSpec = {
            // eslint-disable-next-line @typescript-eslint/naming-convention
            asym_spec: CryptoLayerUtils.asymSpecFromCryptoExchangeOrSignatureAlgorithm(asymmetricKeyAlgorithm),
            cipher: encryptionAlgorithm
                ? CryptoLayerUtils.cipherFromCryptoEncryptionAlgorithm(encryptionAlgorithm)
                : null,
            // eslint-disable-next-line @typescript-eslint/naming-convention
            signing_hash: CryptoLayerUtils.cryptoHashFromCryptoHashAlgorithm(hashAlgorithm),
            ephemeral: false,
            // eslint-disable-next-line @typescript-eslint/naming-convention
            non_exportable: true
        };

        const provider = getProvider(providerIdent);
        const keyPairHandle = await provider.createKeyPair(deviceBoundSpec);

        const result = new DeviceBoundKeyPairHandle();

        [result.providerName, result.id] = await Promise.all([provider.providerName(), keyPairHandle.id()]);

        result.provider = provider;
        result.keyPairHandle = keyPairHandle;

        return result;
    }
}
