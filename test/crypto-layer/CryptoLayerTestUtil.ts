/* eslint-disable @typescript-eslint/naming-convention */
import { AsymmetricKeySpec, Cipher, CryptoHash, KeyPairSpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { defaults } from "lodash";
import { CryptoAsymmetricKeyHandle } from "src/crypto-layer/CryptoAsymmetricKeyHandle";

export interface ParametersKeyPairSpec {
    asymSpec: AsymmetricKeySpec[];
    cipher: (Cipher | null)[];
    signingHash: CryptoHash[];
    ephemeral: boolean[];
    nonExportable: boolean[];
}

export function parameterizedKeyPairSpec(
    name: string,
    testFunction: (spec: KeyPairSpec) => Promise<void>,
    override?: Partial<ParametersKeyPairSpec>
): void {
    const matrix: ParametersKeyPairSpec = defaults(override, {
        asymSpec: ["P256", "Curve25519"],
        cipher: [null, "AesCbc256", "AesGcm256", "AesCbc128", "AesGcm128"],
        signingHash: ["Sha2_512", "Sha2_256"],
        ephemeral: [false, true],
        nonExportable: [false, true]
    });

    matrix.asymSpec.forEach((asym_spec) => {
        matrix.signingHash.forEach((signing_hash) => {
            matrix.cipher.forEach((cipher) => {
                matrix.ephemeral.forEach((ephemeral) => {
                    matrix.nonExportable.forEach((non_exportable) => {
                        // eslint-disable-next-line jest/expect-expect
                        it(`${name} with ${asym_spec}, ${signing_hash}${cipher ? `, ${cipher}` : ""}${ephemeral ? `, ephemeral` : ""}${non_exportable ? `, non_exportable` : ""}`, async function () {
                            const spec: KeyPairSpec = {
                                asym_spec: asym_spec,
                                cipher: cipher,
                                signing_hash: signing_hash,
                                ephemeral: ephemeral,
                                non_exportable: non_exportable
                            };
                            await testFunction(spec);
                        });
                    });
                });
            });
        });
    });
}

export async function expectCryptoSignatureAsymmetricKeyHandle<T extends CryptoAsymmetricKeyHandle>(
    value: T,
    id: string,
    spec: KeyPairSpec,
    providerName: string
): Promise<void> {
    expect(value).to.be.instanceOf(CryptoAsymmetricKeyHandle);
    expect(value.id).to.equal(id);
    expect(value.providerName).to.equal(providerName);
    expect(value.spec).to.deep.equal(spec);
    expect(value.keyPairHandle).to.be.ok;
    expect(value.provider).to.be.ok;
    expect(await value.keyPairHandle.id()).to.equal(id);
    expect(await value.provider.providerName()).to.equal(providerName);
}
