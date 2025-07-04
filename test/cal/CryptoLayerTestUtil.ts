import { CryptoEncryptionAlgorithm, CryptoHashAlgorithm } from "@nmshd/crypto";
import { expect } from "chai";

function formatEncryptionAlgorithm(algo: CryptoEncryptionAlgorithm): string {
    switch (algo) {
        case CryptoEncryptionAlgorithm.AES128_GCM:
            return "AES128_GCM";
        case CryptoEncryptionAlgorithm.AES256_GCM:
            return "AES256_GCM";
        case CryptoEncryptionAlgorithm.XCHACHA20_POLY1305:
            return "XCHACHA20_POLY1305";
        case CryptoEncryptionAlgorithm.AES128_CBC:
            return "AES128_CBC";
        case CryptoEncryptionAlgorithm.AES256_CBC:
            return "AES256_CBC";
        case CryptoEncryptionAlgorithm.CHACHA20_POLY1305:
            return "CHACHA20_POLY1305";
    }
}

function formatHashAlgorithm(algo: CryptoHashAlgorithm): string {
    switch (algo) {
        case CryptoHashAlgorithm.SHA256:
            return "SHA256";
        case CryptoHashAlgorithm.SHA512:
            return "SHA512";
        case CryptoHashAlgorithm.BLAKE2B:
            return "BLAKE2B";
    }
}

export interface ParametersKey {
    cryptoEncryptionAlgorithms: CryptoEncryptionAlgorithm[];
    cryptoHashAlgorithm: CryptoHashAlgorithm[];
}

// Parameters should match `getProviderOrThrow(TEST_PROVIDER_IDENT).getCapabilities()`
const DEFAULT_PARAMETRIZED_KEY_SPEC: ParametersKey = {
    cryptoEncryptionAlgorithms: [
        CryptoEncryptionAlgorithm.AES128_GCM,
        CryptoEncryptionAlgorithm.AES256_GCM,
        CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ],
    cryptoHashAlgorithm: [CryptoHashAlgorithm.SHA512, CryptoHashAlgorithm.SHA256, CryptoHashAlgorithm.BLAKE2B]
};

export function parameterizedKeySpec(
    name: string,
    testFunction: (cryptoAlgorithm: CryptoEncryptionAlgorithm, hashAlgorithm: CryptoHashAlgorithm) => Promise<void>,
    override?: Partial<ParametersKey>
): void {
    const matrix: ParametersKey = {
        ...DEFAULT_PARAMETRIZED_KEY_SPEC,
        ...override
    };

    matrix.cryptoEncryptionAlgorithms.forEach((encryptionAlgo) => {
        matrix.cryptoHashAlgorithm.forEach((hashAlgo) => {
            // eslint-disable-next-line jest/expect-expect
            it(`${name} with ${formatEncryptionAlgorithm(encryptionAlgo)}, ${formatHashAlgorithm(hashAlgo)}`, async function () {
                await testFunction(encryptionAlgo, hashAlgo);
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
        } else {
            await method;
        }
    } catch (err: any) {
        error = err;
    }
    expect(error).to.be.instanceOf(Error);

    if (errorMessageRegexp) {
        if (errorMessageRegexp instanceof RegExp) {
            expect(error!.message).to.match(errorMessageRegexp);
        } else {
            expect(error!.message).to.contain(errorMessageRegexp);
        }
    }
}
