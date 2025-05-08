/* eslint-disable @typescript-eslint/naming-convention */
import {
    CryptoEncryption,
    CryptoEncryptionAlgorithm,
    CryptoPrivateStateTransmit,
    CryptoStateType
} from "@nmshd/crypto";
import { KeySpec } from "@nmshd/rs-crypto-types";
import { expect } from "chai";

export class CryptoStateTest {
    public static run(): void {
        describe("CryptoState", function () {
            const spec: KeySpec = {
                cipher: "XChaCha20Poly1305",
                signing_hash: "Sha2_256",
                ephemeral: false
            };
            const providerIdent = { providerName: "SoftwareProvider" };

            it("should create private transmit state", async function () {
                let key = await CryptoEncryption.generateKeyHandle(providerIdent, spec);

                let stateTx = await CryptoPrivateStateTransmit.generateHandle(key, "");
                expect(stateTx).to.exist;
                expect(stateTx.stateType).to.equal(CryptoStateType.Transmit);
                expect(stateTx.nonce).to.exist;
                expect(stateTx.nonce.buffer.byteLength).to.be.equal(24);
                expect(stateTx.algorithm).to.equal(CryptoEncryptionAlgorithm.XCHACHA20_POLY1305);
                expect(stateTx.counter).to.equal(0);
                expect(stateTx.secretKeyHandle).to.exist;
            });
        });
    }
}
