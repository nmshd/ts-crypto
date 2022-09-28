/* eslint-disable jest/expect-expect */
import {
    CoreBuffer,
    CryptoExchange,
    CryptoExchangeAlgorithm,
    CryptoExchangeKeypair,
    CryptoExchangeSecrets,
    CryptoStream,
    CryptoStreamAddress,
    CryptoStreamState,
    SodiumWrapper
} from "@nmshd/crypto";
import { expect } from "chai";
import { from_base64 } from "libsodium-wrappers-sumo";

class TestableCryptoStream extends CryptoStream {
    public static override getState(address: number) {
        return super.getState(address);
    }

    public static override setState(address: number, state: CoreBuffer): Promise<void> {
        return super.setState(address, state);
    }
}

export class CryptoStreamTest {
    public static run(): void {
        describe("CryptoStream", function () {
            describe("Setup streams", function () {
                let from: CryptoExchangeKeypair;
                let to: CryptoExchangeKeypair;
                let server: CryptoExchangeSecrets;
                let client: CryptoExchangeSecrets;
                let serverTransmissionStream: CryptoStreamState;
                let clientReceivingStream: CryptoStreamAddress;
                let clientTransmissionStream: CryptoStreamState;
                let serverReceivingStream: CryptoStreamAddress;
                let ciphersTo: string[];
                let serverTransmissionStreamSerialized: string;
                let clientReceivingStreamSerialized: string;
                let clientTransmissionStreamSerialized: string;
                let serverReceivingStreamSerialized: string;

                before(async function () {
                    from = await CryptoExchange.generateKeypair(CryptoExchangeAlgorithm.ECDH_X25519);
                    to = await CryptoExchange.generateKeypair(CryptoExchangeAlgorithm.ECDH_X25519);
                    server = await CryptoExchange.deriveRequestor(from, to.publicKey);
                    client = await CryptoExchange.deriveTemplator(to, from.publicKey);

                    // Template
                    serverTransmissionStream = await CryptoStream.initServer(server.transmissionKey);
                    serverTransmissionStreamSerialized = serverTransmissionStream.serialize();
                    console.log(`Server Transmission Stream ${JSON.stringify(serverTransmissionStream)}`);
                    // Request
                    clientReceivingStream = await CryptoStream.initClient(
                        serverTransmissionStream.header,
                        client.receivingKey
                    );
                    clientReceivingStreamSerialized = clientReceivingStream.serialize();
                    console.log(`Client Receiving Stream ${JSON.stringify(clientReceivingStream)}`);
                    clientTransmissionStream = await CryptoStream.initServer(client.transmissionKey);
                    clientTransmissionStreamSerialized = clientTransmissionStream.serialize();
                    console.log(`Client Transmission Stream ${JSON.stringify(clientTransmissionStream)}`);
                    // Request Answer
                    serverReceivingStream = await CryptoStream.initClient(
                        clientTransmissionStream.header,
                        server.receivingKey
                    );
                    serverReceivingStreamSerialized = serverReceivingStream.serialize();
                    console.log(`Server Receiving Stream ${JSON.stringify(serverReceivingStream)}`);

                    ciphersTo = [];
                });

                it("should test", async function () {
                    const sodium = await SodiumWrapper.ready();

                    const senderKeypair = sodium.crypto_kx_keypair();
                    const recipientKeypair = sodium.crypto_kx_keypair();

                    const senderDerived = sodium.crypto_kx_server_session_keys(
                        senderKeypair.publicKey,
                        senderKeypair.privateKey,
                        recipientKeypair.publicKey
                    );
                    const recipientDerived = sodium.crypto_kx_client_session_keys(
                        recipientKeypair.publicKey,
                        recipientKeypair.privateKey,
                        senderKeypair.publicKey
                    );

                    expect(senderDerived.sharedTx.toString()).equals(recipientDerived.sharedRx.toString());
                    expect(senderDerived.sharedRx.toString()).equals(recipientDerived.sharedTx.toString());

                    const senderStream = sodium.crypto_secretstream_xchacha20poly1305_init_push(senderDerived.sharedTx);
                    const senderStreamSerialized = (
                        await TestableCryptoStream.getState(senderStream.state as unknown as number)
                    ).toBase64();
                    const headerSerialized = sodium.to_base64(senderStream.header);
                    const message1Sent = sodium.from_string("message1");
                    const cipher1 = sodium.crypto_secretstream_xchacha20poly1305_push(
                        senderStream.state,
                        message1Sent,
                        null,
                        0
                    );

                    const message2Sent = sodium.from_string("message2");
                    const cipher2 = sodium.crypto_secretstream_xchacha20poly1305_push(
                        senderStream.state,
                        message2Sent,
                        null,
                        0
                    );

                    const header = from_base64(headerSerialized);
                    const recipientStream = sodium.crypto_secretstream_xchacha20poly1305_init_pull(
                        header,
                        recipientDerived.sharedRx
                    );

                    const message1Received = sodium.crypto_secretstream_xchacha20poly1305_pull(
                        recipientStream,
                        cipher1
                    );
                    expect(sodium.to_string(message1Sent)).equals(sodium.to_string(message1Received.message));
                    // Works so far

                    // Time goes by, recipient's device is starting new, ...

                    const header2 = from_base64(headerSerialized);
                    const recipientStream2 = sodium.crypto_secretstream_xchacha20poly1305_init_pull(
                        header2,
                        recipientDerived.sharedRx
                    );
                    const message1Received2 = sodium.crypto_secretstream_xchacha20poly1305_pull(
                        recipientStream2,
                        cipher1
                    );
                    expect(sodium.to_string(message1Sent)).equals(sodium.to_string(message1Received2.message));

                    const message2Received2 = sodium.crypto_secretstream_xchacha20poly1305_pull(
                        recipientStream2,
                        cipher2
                    );
                    expect(sodium.to_string(message2Sent)).equals(sodium.to_string(message2Received2.message));

                    // Works so far, Client was recreated. But all messages must be decrypted again in the correct sequence

                    // Time goes by, sender's device is starting new, ...
                    const senderStream2 = sodium.crypto_secretstream_xchacha20poly1305_init_push(
                        sodium.randombytes_buf(32)
                    );
                    await TestableCryptoStream.setState(
                        senderStream2.state as unknown as number,
                        CoreBuffer.fromBase64(senderStreamSerialized)
                    );

                    const message3Sent = sodium.from_string("message3");
                    const cipher3 = sodium.crypto_secretstream_xchacha20poly1305_push(
                        senderStream2.state,
                        message3Sent,
                        null,
                        0
                    );

                    const message3Received2 = sodium.crypto_secretstream_xchacha20poly1305_pull(
                        recipientStream2,
                        cipher3
                    );
                    expect(sodium.to_string(message3Sent)).equals(sodium.to_string(message3Received2.message));
                });

                it("should encrypt/decrypt stream messages", async function () {
                    let plaintextSent;
                    let receivedObject;
                    let plaintextReceived;
                    let cipher;

                    plaintextSent = "Test";
                    cipher = await CryptoStream.encrypt(
                        CoreBuffer.fromUtf8(plaintextSent),
                        serverTransmissionStream.address
                    );
                    ciphersTo.push(cipher.toBase64());
                    console.log("Cipher", cipher.toBase64());
                    receivedObject = await CryptoStream.decrypt(cipher, clientReceivingStream);
                    console.log("Received", receivedObject);
                    plaintextReceived = receivedObject.toUtf8();
                    console.log(
                        `${plaintextSent === plaintextReceived} Sent ${plaintextSent} Received ${plaintextReceived}`
                    );
                    console.log("Server:", serverTransmissionStream);
                    console.log("Client:", clientReceivingStream);

                    plaintextSent = "Test 2";
                    cipher = await CryptoStream.encrypt(
                        CoreBuffer.fromUtf8(plaintextSent),
                        serverTransmissionStream.address
                    );
                    ciphersTo.push(cipher.toBase64());
                    console.log("Cipher", cipher.toBase64());
                    receivedObject = await CryptoStream.decrypt(cipher, clientReceivingStream);
                    plaintextReceived = receivedObject.toUtf8();
                    console.log("Received", receivedObject);
                    console.log(
                        `${plaintextSent === plaintextReceived} Sent ${plaintextSent} Received ${plaintextReceived}`
                    );
                    console.log("Server:", serverTransmissionStream);
                    console.log("Client:", clientReceivingStream);

                    plaintextSent = "Test 3";
                    cipher = await CryptoStream.encrypt(
                        CoreBuffer.fromUtf8(plaintextSent),
                        serverTransmissionStream.address
                    );
                    ciphersTo.push(cipher.toBase64());
                    console.log("Cipher", cipher.toBase64());
                    receivedObject = await CryptoStream.decrypt(cipher, clientReceivingStream);
                    plaintextReceived = receivedObject.toUtf8();
                    console.log("Received", receivedObject);
                    console.log(
                        `${plaintextSent === plaintextReceived} Sent ${plaintextSent} Received ${plaintextReceived}`
                    );
                    console.log("Server:", serverTransmissionStream);
                    console.log("Client:", clientReceivingStream);
                });

                it("should decrypt stream messages even after new initialization", async function () {
                    // Template
                    serverTransmissionStream = CryptoStreamState.deserialize(serverTransmissionStreamSerialized);
                    console.log(`Server Transmission Stream ${serverTransmissionStream}`);
                    // Request
                    clientReceivingStream = CryptoStreamAddress.deserialize(clientReceivingStreamSerialized);
                    console.log(`Client Receiving Stream ${clientReceivingStream}`);
                    clientTransmissionStream = CryptoStreamState.deserialize(clientTransmissionStreamSerialized);
                    console.log(`Client Transmission Stream ${clientTransmissionStream}`);
                    // Request Answer
                    serverReceivingStream = CryptoStreamAddress.deserialize(serverReceivingStreamSerialized);
                    console.log(`Server Receiving Stream ${serverReceivingStream}`);

                    for (let i = 0, l = ciphersTo.length; i < l; i++) {
                        const cipher = ciphersTo[i];
                        const buffer = CoreBuffer.fromBase64(cipher);
                        console.log("Cipher", buffer.toBase64());
                        const plaintext = await CryptoStream.decrypt(buffer, clientReceivingStream);
                        expect(plaintext).to.exist;
                        console.log("Plaintext: ", plaintext.toUtf8());
                    }
                });
            });
        });
    }
}
