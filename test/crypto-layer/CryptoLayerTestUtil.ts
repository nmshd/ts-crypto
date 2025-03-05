/* eslint-disable @typescript-eslint/naming-convention */
import { AsymmetricKeySpec, Cipher, CryptoHash, KeyPairSpec } from "@nmshd/rs-crypto-types";
import { defaultsDeep } from "lodash";

export function parameterizedKeyPairSpec(
    name: string,
    testFunction: (spec: KeyPairSpec) => Promise<void>,
    override?: {
        asymSpec?: AsymmetricKeySpec[];
        cipher?: (Cipher | null)[];
        signingHash?: CryptoHash[];
        ephemeral?: boolean[];
        nonExportable?: boolean[];
    }
): void {
    const matrix: {
        asymSpec: AsymmetricKeySpec[];
        cipher: (Cipher | null)[];
        signingHash: CryptoHash[];
        ephemeral: boolean[];
        nonExportable: boolean[];
    } = defaultsDeep(override, {
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
                        it(`${name} with ${asym_spec}, ${signing_hash}, cipher=${cipher}, ephemeral=${ephemeral} and non_exportable=${non_exportable}`, async function () {
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
