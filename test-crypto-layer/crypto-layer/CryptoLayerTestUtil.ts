/* eslint-disable @typescript-eslint/naming-convention */
import { Cipher, CryptoHash, KeySpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";

export interface ParametersKeySpec {
    cipher: Cipher[];
    signingHash: CryptoHash[];
    ephemeral: boolean[];
    nonExportable: boolean[];
}

// Parameters should match `getProviderOrThrow(TEST_PROVIDER_IDENT).getCapabilities()`
const DEFAULT_PARAMETRIZED_KEY_SPEC: ParametersKeySpec = {
    cipher: ["AesGcm256", "AesGcm128", "XChaCha20Poly1305"],
    signingHash: ["Sha2_256", "Sha2_512"],
    ephemeral: [false, true],
    nonExportable: [false, true]
};

export function parameterizedKeySpec(
    name: string,
    testFunction: (spec: KeySpec) => Promise<void>,
    override?: Partial<ParametersKeySpec>
): void {
    const matrix: ParametersKeySpec = {
        ...DEFAULT_PARAMETRIZED_KEY_SPEC,
        ...override
    };

    matrix.signingHash.forEach((signing_hash) => {
        matrix.cipher.forEach((cipher) => {
            matrix.ephemeral.forEach((ephemeral) => {
                matrix.nonExportable.forEach((nonExportable) => {
                    // eslint-disable-next-line jest/expect-expect
                    it(`${name} with ${signing_hash}, ${cipher}${ephemeral ? `, ephemeral` : ""}${nonExportable ? `, non_exportable` : ""}`, async function () {
                        const spec: KeySpec = {
                            cipher: cipher,
                            signing_hash: signing_hash,
                            ephemeral: ephemeral,
                            non_exportable: nonExportable
                        };
                        await testFunction(spec);
                    });
                });
            });
        });
    });
}

export async function expectThrows(
    method: Function | Promise<any>,
    errorMessageRegexp?: RegExp | string
): Promise<void> {
    let error: Error | undefined;
    try {
        if (typeof method === "function") {
            await method();
        }
    } catch (err: any) {
        error = err;
    }
    expect(error).to.be.instanceOf(Error);
    if (errorMessageRegexp) {
        expect(error!.message).to.match(new RegExp(`^${errorMessageRegexp}`));
    }
}
