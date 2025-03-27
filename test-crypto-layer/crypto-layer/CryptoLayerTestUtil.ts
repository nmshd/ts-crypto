/* eslint-disable @typescript-eslint/naming-convention */
import { AsymmetricKeySpec, Cipher, CryptoHash, KeyPairSpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { defaults } from "lodash";

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

export async function specEquals<T>(
    value: { keyPairHandle: { spec: () => Promise<T> }; spec: T } | { keyHandle: { spec: () => Promise<T> }; spec: T },
    spec: T
) {
    expect(value.spec).to.deep.equal(spec);
    if ("keyPairHandle" in value) {
        expect(await value.keyPairHandle.spec()).to.deep.equal(spec);
    } else {
        expect(await value.keyHandle.spec()).to.deep.equal(spec);
    }
}

export async function idEquals(
    value:
        | { keyPairHandle: { id: () => Promise<string> }; id: string }
        | { keyHandle: { id: () => Promise<string> }; id: string },
    id: string
) {
    expect(value.id).to.eq(id);
    if ("keyPairHandle" in value) {
        expect(await value.keyPairHandle.id()).to.deep.equal(id);
    } else {
        expect(await value.keyHandle.id()).to.deep.equal(id);
    }
}

export async function idSpecProviderNameEqual<T>(
    value:
        | {
              keyPairHandle: { id: () => Promise<string>; spec: () => Promise<T> };
              id: string;
              spec: T;
              providerName: string;
          }
        | {
              keyHandle: { id: () => Promise<string>; spec: () => Promise<T> };
              id: string;
              spec: T;
              providerName: string;
          },
    id: string,
    spec: T,
    providerName: string
) {
    await Promise.all([specEquals(value, spec), idEquals(value, id)]);
    expect(value.providerName).to.eq(providerName);
}
