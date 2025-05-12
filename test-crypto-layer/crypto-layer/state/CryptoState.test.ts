/* eslint-disable @typescript-eslint/naming-convention */
import {
    CoreBuffer,
    CryptoCipher,
    CryptoEncryption,
    CryptoEncryptionAlgorithm,
    CryptoError,
    CryptoPrivateStateReceiveHandle,
    CryptoPrivateStateTransmit,
    CryptoPrivateStateTransmitHandle,
    CryptoPublicStateHandle,
    CryptoSecretKeyHandle,
    CryptoStateType,
    ICryptoPrivateStateHandleSerialized
} from "@nmshd/crypto";
import { KeySpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";
import { CryptoTestUtil } from "../../../test/CryptoTestUtil";

export class CryptoStateTest {
    public static run(): void {
        describe("CryptoState", function () {
            const spec: KeySpec = {
                cipher: "XChaCha20Poly1305",
                signing_hash: "Sha2_256",
                ephemeral: false
            };
            const providerIdent = { providerName: "SoftwareProvider" };
            let key: CryptoSecretKeyHandle;
            let stateTx: CryptoPrivateStateTransmitHandle;
            let stateRx: CryptoPrivateStateReceiveHandle;
            let publicState: CryptoPublicStateHandle;
            let serializedTx: ICryptoPrivateStateHandleSerialized;
            let serializedRx: ICryptoPrivateStateHandleSerialized;
            const allCiphers: CryptoCipher[] = [];
            let ciphersInBetween: CryptoCipher[];

            it("should create private transmit state", async function () {
                key = await CryptoEncryption.generateKeyHandle(providerIdent, spec);

                stateTx = await CryptoPrivateStateTransmit.generateHandle(key, "");
                expect(stateTx).to.exist;
                expect(stateTx.stateType).to.equal(CryptoStateType.Transmit);
                expect(stateTx.nonce).to.exist;
                expect(stateTx.nonce.buffer.byteLength).to.be.equal(24);
                expect(stateTx.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                expect(stateTx.counter).to.equal(0);
                expect(stateTx.secretKeyHandle).to.exist;
            });

            it("should create public state out of private transmit state", function () {
                publicState = stateTx.toPublicState();
                expect(publicState).to.exist;
                expect(publicState.algorithm).to.exist;
                expect(publicState.nonce).to.exist;
                expect(publicState.nonce).not.to.equal(stateTx.nonce);
                expect(publicState.nonce.toBase64URL()).to.equal(stateTx.nonce.toBase64URL());
                expect(publicState.nonce.buffer.byteLength).to.be.equal(24);
                expect(publicState.stateType).to.equal(CryptoStateType.Transmit);
                expect(publicState.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                const publicAny: any = publicState as any;
                expect(publicAny.secretKey).not.to.exist;
                expect(publicAny.secretKeyHandle).not.to.exist;
                expect(publicAny.counter).not.to.exist;
            });

            it("should create private receive state out of public state", async function () {
                stateRx = await CryptoPrivateStateReceiveHandle.fromPublicState(publicState, key);
                expect(stateRx).to.exist;
                expect(stateRx.stateType).to.equal(CryptoStateType.Receive);
                expect(stateRx.nonce).to.exist;
                expect(stateRx.nonce.buffer.byteLength).to.be.equal(24);
                expect(stateRx.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                expect(stateRx.counter).to.equal(0);
                expect(stateRx.secretKeyHandle).to.exist;
                expect(stateRx.secretKeyHandle.id).to.equal(key.id);
            });

            it("should still have the correct states even if publicState is cleared", function () {
                publicState.clear();
                expect(CryptoTestUtil.isCleared(publicState.nonce)).to.be.true;
                expect(CryptoTestUtil.isCleared(stateTx.nonce)).to.be.false;
                expect(CryptoTestUtil.isCleared(stateRx.nonce)).to.be.false;
            });

            it("should encrypt and decrypt a message", async function () {
                const message = "test";
                const ciphers: CryptoCipher[] = [];
                for (let i = 0; i < 10; i++) {
                    ciphers.push(await stateTx.encrypt(CoreBuffer.fromUtf8(message)));
                }
                allCiphers.push(...ciphers);
                expect(ciphers.length).to.equal(10);
                expect(stateTx.counter).to.equal(10);

                for (let i = 0; i < 10; i++) {
                    const cipher = ciphers[i];
                    const plaintext = await stateTx.decrypt(cipher);
                    expect(plaintext.toUtf8()).to.be.equal(message);
                }

                expect(ciphers.length).to.equal(10);
                expect(stateTx.counter).to.equal(10);

                for (let i = 0; i < 10; i++) {
                    const cipher = ciphers[i];
                    const plaintext = await stateRx.decrypt(cipher);
                    expect(plaintext.toUtf8()).to.be.equal(message);
                }

                expect(stateRx.counter).to.equal(10);
            });

            it("should throw an error for out of order messages", async function () {
                const message = "test";
                ciphersInBetween = [];
                for (let i = 0; i < 10; i++) {
                    ciphersInBetween.push(await stateTx.encrypt(CoreBuffer.fromUtf8(message)));
                }
                allCiphers.push(...ciphersInBetween);
                expect(ciphersInBetween.length).to.equal(10);
                expect(stateTx.counter).to.equal(20);

                let error;
                try {
                    await stateRx.decrypt(ciphersInBetween[1]);
                } catch (e) {
                    error = e;
                }
                expect(stateRx.counter).to.equal(10);

                expect(error).to.be.instanceOf(CryptoError);
            });

            it("should serialize the states", async function () {
                serializedTx = await stateTx.toJSON();
                serializedRx = await stateRx.toJSON();

                expect(serializedTx.alg).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                expect(serializedTx.cnt).to.equal(20);
                expect(serializedTx.nnc).to.be.a("string");
                expect(serializedTx.typ).to.equal(CryptoStateType.Transmit);

                expect(serializedRx.alg).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                expect(serializedRx.cnt).to.equal(10);
                expect(serializedRx.nnc).to.be.a("string");
                expect(serializedRx.typ).to.equal(CryptoStateType.Receive);
            });

            it("should deserialize the states (1)", async function () {
                stateTx = await CryptoPrivateStateTransmitHandle.fromJSON(serializedTx);

                expect(stateTx).to.exist;
                expect(stateTx.stateType).to.equal(CryptoStateType.Transmit);
                expect(stateTx.nonce).to.exist;
                expect(stateTx.nonce.buffer.byteLength).to.be.equal(24);
                expect(stateTx.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                expect(stateTx.counter).to.equal(20);
                expect(stateTx.secretKeyHandle).to.exist;
                expect(stateTx.secretKeyHandle.keyHandle).exist;

                stateRx = await CryptoPrivateStateReceiveHandle.fromJSON(serializedRx);

                expect(stateRx).to.exist;
                expect(stateRx.stateType).to.equal(CryptoStateType.Receive);
                expect(stateRx.nonce).to.exist;
                expect(stateRx.nonce.buffer.byteLength).to.be.equal(24);
                expect(stateRx.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                expect(stateRx.counter).to.equal(10);
                expect(stateRx.secretKeyHandle).to.exist;
                expect(stateRx.secretKeyHandle.keyHandle).exist;

                expect(stateRx.nonce.toBase64URL()).to.equal(stateTx.nonce.toBase64URL());
                expect(stateRx.secretKeyHandle.id).to.equal(stateTx.secretKeyHandle.id);
            });

            it("should deserialize the states (2)", async function () {
                let stateTx = await CryptoPrivateStateTransmitHandle.fromJSON(serializedTx);
                const serialized = stateTx.serialize();
                stateTx = await CryptoPrivateStateTransmitHandle.deserialize(serialized);

                expect(stateTx).to.exist;
                expect(stateTx.stateType).to.equal(CryptoStateType.Transmit);
                expect(stateTx.nonce).to.exist;
                expect(stateTx.nonce.buffer.byteLength).to.be.equal(24);
                expect(stateTx.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                expect(stateTx.counter).to.equal(20);
                expect(stateTx.secretKeyHandle).to.exist;

                let stateRx = await CryptoPrivateStateReceiveHandle.fromJSON(serializedRx);
                const serialized2 = stateRx.serialize();
                stateRx = await CryptoPrivateStateReceiveHandle.deserialize(serialized2);

                expect(stateRx).to.exist;
                expect(stateRx.stateType).to.equal(CryptoStateType.Receive);
                expect(stateRx.nonce).to.exist;
                expect(stateRx.nonce.buffer.byteLength).to.be.equal(24);
                expect(stateRx.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                expect(stateRx.counter).to.equal(10);
                expect(stateRx.secretKeyHandle).to.exist;

                expect(stateRx.nonce.toBase64URL()).to.equal(stateTx.nonce.toBase64URL());
                expect(stateRx.secretKeyHandle.id).to.equal(stateTx.secretKeyHandle.id);
            });

            it("should decrypt the rest of the messages after deserialization", async function () {
                const message = "test";
                for (let i = 0; i < 10; i++) {
                    const cipher = ciphersInBetween[i];
                    const plaintext = await stateRx.decrypt(cipher);
                    expect(plaintext.toUtf8()).to.be.equal(message);
                }
                expect(stateRx.counter).to.equal(20);
            });

            it("should encrypt and decrypt a message after serialization", async function () {
                const message = "test";
                const ciphers: CryptoCipher[] = [];
                for (let i = 0; i < 10; i++) {
                    ciphers.push(await stateTx.encrypt(CoreBuffer.fromUtf8(message)));
                }
                allCiphers.push(...ciphers);
                expect(ciphers.length).to.equal(10);
                expect(stateTx.counter).to.equal(30);

                for (let i = 0; i < 10; i++) {
                    const cipher = ciphers[i];
                    const plaintext = await stateRx.decrypt(cipher);
                    expect(plaintext.toUtf8()).to.be.equal(message);
                }

                expect(stateRx.counter).to.equal(30);
            });

            it("should decrypt messages a second time if counter is omitted", async function () {
                const message = "test";

                for (let i = 0; i < 10; i++) {
                    const cipher = ciphersInBetween[i];
                    const plaintext = await stateRx.decrypt(cipher, true);
                    expect(plaintext.toUtf8()).to.be.equal(message);
                }

                expect(stateRx.counter).to.equal(30);
            });

            it("should throw an error for out of order messages after deserialization", async function () {
                const message = "test";
                ciphersInBetween = [];
                for (let i = 0; i < 10; i++) {
                    ciphersInBetween.push(await stateTx.encrypt(CoreBuffer.fromUtf8(message)));
                }
                allCiphers.push(...ciphersInBetween);
                expect(ciphersInBetween.length).to.equal(10);
                expect(stateTx.counter).to.equal(40);

                let error;
                try {
                    await stateRx.decrypt(ciphersInBetween[1]);
                } catch (e) {
                    error = e;
                }
                expect(stateRx.counter).to.equal(30);

                expect(error).to.be.instanceOf(CryptoError);
            });

            it("should decrypt messages after an error occured", async function () {
                const message = "test";

                for (let i = 0; i < 10; i++) {
                    const cipher = ciphersInBetween[i];
                    const plaintext = await stateRx.decrypt(cipher);
                    expect(plaintext.toUtf8()).to.be.equal(message);
                }

                expect(stateRx.counter).to.equal(40);
            });

            it("should decrypt all ciphers for stateRx if counter is omitted", async function () {
                const message = "test";

                for (const cipher of allCiphers) {
                    const plaintext = await stateRx.decrypt(cipher, true);
                    expect(plaintext.toUtf8()).to.be.equal(message);
                }

                expect(stateRx.counter).to.equal(40);
            });

            it("should decrypt all ciphers for stateTx", async function () {
                const message = "test";

                for (const cipher of allCiphers) {
                    const plaintext = await stateTx.decrypt(cipher);
                    expect(plaintext.toUtf8()).to.be.equal(message);
                }

                expect(stateTx.counter).to.equal(40);
            });
        });
    }
}
