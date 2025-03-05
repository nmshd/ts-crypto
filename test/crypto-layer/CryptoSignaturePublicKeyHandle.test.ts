import { expect } from "chai";
import { CryptoSignaturePublicKeyHandle } from "src/crypto-layer/signature/CryptoSignaturePublicKeyHandle";
import { CryptoSignatures } from "src/signature/CryptoSignatures";
import {
    expectCryptoSignatureAsymmetricKeyHandle,
    parameterizedKeyPairSpec,
    ParametersKeyPairSpec
} from "./CryptoLayerTestUtil";

export class CryptoSignaturePublicKeyHandleTest {
    public static run(): void {
        describe("CryptoSignaturePublicKeyHandle", function () {
            describe("CryptoSignaturePublicKeyHandle SoftwareProvider P256 Sha2_512", function () {
                const matrix: ParametersKeyPairSpec = {
                    asymSpec: ["P256"],
                    cipher: [null],
                    signingHash: ["Sha2_512"],
                    ephemeral: [false],
                    nonExportable: [false, true]
                };
                const providerIdent = { providerName: "SoftwareProvider" };

                parameterizedKeyPairSpec(
                    "toJSON() and fromJSON()",
                    async function (spec) {
                        const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                        const publicKeyHandle = cryptoKeyPairHandle.publicKey;
                        const id = publicKeyHandle.id;
                        const providerName = publicKeyHandle.providerName;

                        const serializedpublicKeyHandle = publicKeyHandle.toJSON();
                        expect(serializedpublicKeyHandle).to.be.instanceOf(Object);
                        expect(serializedpublicKeyHandle.cid).to.equal(id);
                        expect(serializedpublicKeyHandle.pnm).to.equal(providerName);
                        expect(serializedpublicKeyHandle.spc).to.deep.equal(spec);
                        expect(serializedpublicKeyHandle["@type"]).to.equal("CryptoSignaturePublicKeyHandle");

                        const loadedpublicKeyHandle =
                            await CryptoSignaturePublicKeyHandle.fromJSON(serializedpublicKeyHandle);
                        await expectCryptoSignatureAsymmetricKeyHandle(loadedpublicKeyHandle, id, spec, providerName);
                    },
                    matrix
                );

                parameterizedKeyPairSpec(
                    "toBase64() and fromBase64()",
                    async function (spec) {
                        const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                        const publicKeyHandle = cryptoKeyPairHandle.publicKey;
                        const id = publicKeyHandle.id;
                        const providerName = publicKeyHandle.providerName;

                        const serializedpublicKey = publicKeyHandle.toBase64();
                        expect(serializedpublicKey).to.be.ok;
                        const deserializedpublicKey = CryptoSignaturePublicKeyHandle.fromBase64(serializedpublicKey);
                        await expectCryptoSignatureAsymmetricKeyHandle(
                            await deserializedpublicKey,
                            id,
                            spec,
                            providerName
                        );
                    },
                    matrix
                );

                parameterizedKeyPairSpec(
                    "from() ICryptoSignaturePublicKeyHandle",
                    async function (spec) {
                        const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                        const publicKeyHandle = cryptoKeyPairHandle.publicKey;
                        const id = publicKeyHandle.id;
                        const providerName = publicKeyHandle.providerName;

                        const loadedpublicKeyHandle = await CryptoSignaturePublicKeyHandle.from({
                            spec: spec,
                            id: id,
                            providerName: providerName
                        });
                        await expectCryptoSignatureAsymmetricKeyHandle(loadedpublicKeyHandle, id, spec, providerName);
                    },
                    matrix
                );

                parameterizedKeyPairSpec(
                    "from() CryptoSignaturePublicKeyHandle",
                    async function (spec) {
                        const cryptoKeyPairHandle = await CryptoSignatures.generateKeypairHandle(providerIdent, spec);
                        const publicKeyHandle = cryptoKeyPairHandle.publicKey;
                        const id = publicKeyHandle.id;
                        const providerName = publicKeyHandle.providerName;

                        const loadedpublicKeyHandle = await CryptoSignaturePublicKeyHandle.from(publicKeyHandle);
                        await expectCryptoSignatureAsymmetricKeyHandle(loadedpublicKeyHandle, id, spec, providerName);
                    },
                    matrix
                );
            });
        });
    }
}
