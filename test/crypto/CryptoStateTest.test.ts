import { Serializable } from "@js-soft/ts-serval";
import {
    CoreBuffer,
    CryptoCipher,
    CryptoEncryptionAlgorithm,
    CryptoError,
    CryptoPrivateStateReceive,
    CryptoPrivateStateTransmit,
    CryptoPublicState,
    CryptoStateType,
    ICryptoPrivateStateSerialized
} from "@nmshd/crypto";
import { expect } from "chai";
import { CryptoTestUtil } from "../CryptoTestUtil";

export class CryptoStateTest {
    public static run(): void {
        describe("CryptoState", function () {
            let sharedKey: CoreBuffer;
            let stateTx: CryptoPrivateStateTransmit;
            let publicState: CryptoPublicState;
            let stateRx: CryptoPrivateStateReceive;
            let serializedTx: ICryptoPrivateStateSerialized;
            let serializedRx: ICryptoPrivateStateSerialized;
            let ciphersInBetween: CryptoCipher[];
            const allCiphers: CryptoCipher[] = [];

            before(function () {
                sharedKey = CoreBuffer.random(32);
            });

            it("should create private transmit state", function () {
                stateTx = CryptoPrivateStateTransmit.generate(sharedKey, "");
                expect(stateTx).to.exist;
                expect(stateTx.stateType).to.equal(CryptoStateType.Transmit);
                expect(stateTx.nonce).to.exist;
                expect(stateTx.nonce.buffer.byteLength).to.be.equal(24);
                expect(stateTx.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                expect(stateTx.counter).to.equal(0);
                expect(stateTx.secretKey).to.exist;
                expect(stateTx.secretKey.buffer.byteLength).to.be.equal(32);
                expect(stateTx.secretKey.toBase64URL()).to.equal(sharedKey.toBase64URL());
                expect(stateTx.secretKey.buffer.toString()).to.equal(sharedKey.buffer.toString());
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
                expect(publicAny.counter).not.to.exist;
            });

            it("should create private receive state out of public state", function () {
                stateRx = CryptoPrivateStateReceive.fromPublicState(publicState, sharedKey);
                expect(stateRx).to.exist;
                expect(stateRx.stateType).to.equal(CryptoStateType.Receive);
                expect(stateRx.nonce).to.exist;
                expect(stateRx.nonce.buffer.byteLength).to.be.equal(24);
                expect(stateRx.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                expect(stateRx.counter).to.equal(0);
                expect(stateRx.secretKey).to.exist;
                expect(stateRx.secretKey.buffer.byteLength).to.be.equal(32);
                expect(stateRx.secretKey.toBase64URL()).to.equal(sharedKey.toBase64URL());
                expect(stateRx.secretKey.toString()).to.equal(sharedKey.toString());
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

            it("should serialize the states", function () {
                serializedTx = stateTx.toJSON();
                serializedRx = stateRx.toJSON();

                expect(serializedTx.alg).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                expect(serializedTx.cnt).to.equal(20);
                expect(serializedTx.nnc).to.be.a("string");
                expect(serializedTx.key).to.be.a("string");
                expect(serializedTx.typ).to.equal(CryptoStateType.Transmit);

                expect(serializedRx.alg).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                expect(serializedRx.cnt).to.equal(10);
                expect(serializedRx.nnc).to.be.a("string");
                expect(serializedRx.key).to.be.a("string");
                expect(serializedRx.typ).to.equal(CryptoStateType.Receive);
            });

            it("should clear the secret key out of all states", function () {
                sharedKey.clear();
                expect(CryptoTestUtil.isCleared(sharedKey)).to.be.true;

                stateRx.clear();
                expect(CryptoTestUtil.isCleared(stateRx.secretKey)).to.be.true;

                stateTx.clear();
                expect(CryptoTestUtil.isCleared(stateTx.secretKey)).to.be.true;
            });

            it("should deserialize the states (1)", function () {
                stateTx = CryptoPrivateStateTransmit.fromJSON(serializedTx);

                expect(stateTx).to.exist;
                expect(stateTx.stateType).to.equal(CryptoStateType.Transmit);
                expect(stateTx.nonce).to.exist;
                expect(stateTx.nonce.buffer.byteLength).to.be.equal(24);
                expect(stateTx.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                expect(stateTx.counter).to.equal(20);
                expect(stateTx.secretKey).to.exist;
                expect(stateTx.secretKey.buffer.byteLength).to.be.equal(32);

                stateRx = CryptoPrivateStateReceive.fromJSON(serializedRx);

                expect(stateRx).to.exist;
                expect(stateRx.stateType).to.equal(CryptoStateType.Receive);
                expect(stateRx.nonce).to.exist;
                expect(stateRx.nonce.buffer.byteLength).to.be.equal(24);
                expect(stateRx.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                expect(stateRx.counter).to.equal(10);
                expect(stateRx.secretKey).to.exist;
                expect(stateRx.secretKey.buffer.byteLength).to.be.equal(32);

                expect(stateRx.nonce.toBase64URL()).to.equal(stateTx.nonce.toBase64URL());
                expect(stateRx.secretKey.toBase64URL()).to.equal(stateTx.secretKey.toBase64URL());
            });

            it("should deserialize the states (2)", function () {
                let stateTx = CryptoPrivateStateTransmit.fromJSON(serializedTx);
                const serialized = stateTx.serialize();
                stateTx = CryptoPrivateStateTransmit.deserialize(serialized);

                expect(stateTx).to.exist;
                expect(stateTx.stateType).to.equal(CryptoStateType.Transmit);
                expect(stateTx.nonce).to.exist;
                expect(stateTx.nonce.buffer.byteLength).to.be.equal(24);
                expect(stateTx.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                expect(stateTx.counter).to.equal(20);
                expect(stateTx.secretKey).to.exist;
                expect(stateTx.secretKey.buffer.byteLength).to.be.equal(32);

                let stateRx = CryptoPrivateStateReceive.fromJSON(serializedRx);
                const serialized2 = stateRx.serialize();
                stateRx = CryptoPrivateStateReceive.deserialize(serialized2);

                expect(stateRx).to.exist;
                expect(stateRx.stateType).to.equal(CryptoStateType.Receive);
                expect(stateRx.nonce).to.exist;
                expect(stateRx.nonce.buffer.byteLength).to.be.equal(24);
                expect(stateRx.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                expect(stateRx.counter).to.equal(10);
                expect(stateRx.secretKey).to.exist;
                expect(stateRx.secretKey.buffer.byteLength).to.be.equal(32);

                expect(stateRx.nonce.toBase64URL()).to.equal(stateTx.nonce.toBase64URL());
                expect(stateRx.secretKey.toBase64URL()).to.equal(stateTx.secretKey.toBase64URL());
            });

            it("should deserialize the states from @type", function () {
                let stateTx = CryptoPrivateStateTransmit.fromJSON(serializedTx);
                const serialized = stateTx.serialize();
                stateTx = Serializable.deserializeUnknown(serialized) as CryptoPrivateStateTransmit;
                expect(stateTx).instanceOf(CryptoPrivateStateTransmit);
                expect(stateTx).to.exist;
                expect(stateTx.stateType).to.equal(CryptoStateType.Transmit);
                expect(stateTx.nonce).to.exist;
                expect(stateTx.nonce.buffer.byteLength).to.be.equal(24);
                expect(stateTx.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                expect(stateTx.counter).to.equal(20);
                expect(stateTx.secretKey).to.exist;
                expect(stateTx.secretKey.buffer.byteLength).to.be.equal(32);

                let stateRx = CryptoPrivateStateReceive.fromJSON(serializedRx);
                const serialized2 = stateRx.serialize();
                stateRx = Serializable.deserializeUnknown(serialized2) as CryptoPrivateStateReceive;
                expect(stateRx).instanceOf(CryptoPrivateStateReceive);
                expect(stateRx).to.exist;
                expect(stateRx.stateType).to.equal(CryptoStateType.Receive);
                expect(stateRx.nonce).to.exist;
                expect(stateRx.nonce.buffer.byteLength).to.be.equal(24);
                expect(stateRx.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                expect(stateRx.counter).to.equal(10);
                expect(stateRx.secretKey).to.exist;
                expect(stateRx.secretKey.buffer.byteLength).to.be.equal(32);

                expect(stateRx.nonce.toBase64URL()).to.equal(stateTx.nonce.toBase64URL());
                expect(stateRx.secretKey.toBase64URL()).to.equal(stateTx.secretKey.toBase64URL());
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
