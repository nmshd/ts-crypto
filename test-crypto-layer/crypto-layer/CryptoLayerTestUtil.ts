/* eslint-disable @typescript-eslint/naming-convention */
import { Cipher, CryptoHash, KeySpec } from "@nmshd/rs-crypto-types";

export interface ParametersKeySpec {
    cipher: Cipher[];
    signingHash: CryptoHash[];
    ephemeral: boolean[];
}

// Parameters should match `getProviderOrThrow(TEST_PROVIDER_IDENT).getCapabilities()`
const DEFAULT_PARAMETRIZED_KEY_SPEC: ParametersKeySpec = {
    cipher: ["AesGcm256", "AesGcm128", "XChaCha20Poly1305"],
    signingHash: ["Sha2_256", "Sha2_512"],
    ephemeral: [false, true]
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
                // eslint-disable-next-line jest/expect-expect
                it(`${name} with ${signing_hash}${cipher}${ephemeral ? `, ephemeral` : ""}`, async function () {
                    const spec: KeySpec = {
                        cipher: cipher,
                        signing_hash: signing_hash,
                        ephemeral: ephemeral
                    };
                    await testFunction(spec);
                });
            });
        });
    });
}
