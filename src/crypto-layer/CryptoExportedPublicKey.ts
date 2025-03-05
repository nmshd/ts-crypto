import { serialize, type, validate } from "@js-soft/ts-serval";
import { KeyPairHandle, KeyPairSpec, Provider } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "src/CoreBuffer";
import { CryptoSerializable } from "src/CryptoSerializable";
import { getProviderOrThrow, ProviderIdentifier } from "./CryptoLayerProviders";
import { CryptoPublicKeyHandle } from "./CryptoPublicKeyHandle";

@type("CryptoExportedPublicKey")
export class CryptoExportedPublicKey extends CryptoSerializable {
    @validate()
    @serialize()
    public rawPublicKey: CoreBuffer;

    @validate()
    @serialize()
    public spec: KeyPairSpec;

    public async into<T extends CryptoPublicKeyHandle>(
        constructor: { newFromProviderAndKeyPairHandle(provider: Provider, keyPairHandle: KeyPairHandle): Promise<T> },
        providerIdent: ProviderIdentifier
    ): Promise<T> {
        const provider = getProviderOrThrow(providerIdent);
        const keyPairHandle = await provider.importPublicKey(this.spec, this.rawPublicKey.buffer);
        return await constructor.newFromProviderAndKeyPairHandle(provider, keyPairHandle);
    }

    public static async from(publicKeyHandle: CryptoPublicKeyHandle): Promise<CryptoExportedPublicKey> {
        const exportedPublicKey = new CryptoExportedPublicKey();
        exportedPublicKey.spec = publicKeyHandle.spec;
        exportedPublicKey.rawPublicKey = new CoreBuffer(await publicKeyHandle.keyPairHandle.getPublicKey());
        return exportedPublicKey;
    }
}
