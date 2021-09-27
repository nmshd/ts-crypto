import { CoreBuffer, Encoding } from "@nmshd/crypto";
import { expect } from "chai";

export class BufferTest {
    public static run(): void {
        describe("Buffer", function () {
            it("should return a buffer with a length property", function () {
                const buffer = new CoreBuffer([1, 3, 4]);
                expect(buffer).to.be.of.length(3);
            });

            it("toString('csv') should return with a comma separated list", function () {
                const buffer = new CoreBuffer([84, 97, 116, 252]);
                expect(buffer.toString(Encoding.Csv)).to.equal("84,97,116,252");
            });

            it("toString('hex') should return with hex values", function () {
                const buffer = new CoreBuffer([84, 97, 116, 252]);
                expect(buffer.toString(Encoding.Hex)).to.equal("546174fc");
            });

            it("toString('latin1') should return with Latin1 string", function () {
                const buffer = new CoreBuffer([84, 97, 116, 252]);
                expect(buffer.toString(Encoding.Latin1)).to.equal("Tatü");
            });

            it("toString('ascii') should return with ASCII string", function () {
                const buffer = new CoreBuffer([84, 97, 116, 252]);
                expect(buffer.toString(Encoding.Ascii)).to.equal("Tat|");
            });

            it("toString('utf8') should return with UTF-8 string", function () {
                const buffer = new CoreBuffer([84, 97, 116, 195, 188]);
                expect(buffer.toString(Encoding.Utf8)).to.equal("Tatü");
            });

            it("toString('base64') should return with Base64 string (ASCII input)", function () {
                const buffer = new CoreBuffer([84, 97, 116, 252]);
                expect(buffer.toString(Encoding.Base64)).to.equal("VGF0/A==");
            });

            it("toString('base64') should return with Base64 string (UTF-8 input)", function () {
                const buffer = new CoreBuffer([84, 97, 116, 195, 188]);
                expect(buffer.toString(Encoding.Base64)).to.equal("VGF0w7w=");
            });

            it("toString('pem') should return with PEM string", function () {
                const buffer = new CoreBuffer([84, 97, 116, 195, 188]);
                expect(buffer.toString(Encoding.Pem)).to.equal(
                    "-----BEGIN PUBLIC KEY-----\r\nVGF0w7w=\r\n-----END PUBLIC KEY-----\r\n"
                );
            });

            it("should return with a Base58 representation", function () {
                const buffer = CoreBuffer.fromString(
                    "003c176e659bea0f29a3e9bf7880c112b1b31b4dc826268187",
                    Encoding.Hex
                );
                const encoded = buffer.toBase58();

                expect(encoded).to.equal("16UjcYNBG9GTK4uq2f7yYEbuifqCzoLMGS");
            });

            it("should parse a Base58 representation", function () {
                const encoded = "16UjcYNBG9GTK4uq2f7yYEbuifqCzoLMGS";
                const buffer = CoreBuffer.fromBase58(encoded);

                expect(buffer.toString(Encoding.Hex)).to.equal("003c176e659bea0f29a3e9bf7880c112b1b31b4dc826268187");
            });

            it("toString('pem', 'EC PRIVATE KEY') should return with PEM string", function () {
                const buffer = new CoreBuffer([84, 97, 116, 195, 188]);
                expect(buffer.toString(Encoding.Pem, "EC PRIVATE KEY")).to.equal(
                    "-----BEGIN EC PRIVATE KEY-----\r\nVGF0w7w=\r\n-----END EC PRIVATE KEY-----\r\n"
                );
            });

            it("toString('pem') should split Base64 content after 64 characters", function () {
                const buffer = new CoreBuffer([
                    84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84, 97,
                    116, 195, 188, 84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84, 97, 116,
                    195, 188, 84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84, 97, 116, 195,
                    188, 84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84,
                    97, 116, 195, 188
                ]);
                expect(buffer.toString(Encoding.Pem)).to.equal(
                    "-----BEGIN PUBLIC KEY-----\r\nVGF0w7xUYXTDvFRhdMO8VGF0w7xUYXTDvFRhdMO8VGF0w7xUYXTDvFRhdMO8VGF0\r\nw7xUYXTDvFRhdMO8VGF0w7xUYXTDvFRhdMO8VGF0w7xUYXTDvFRhdMO8\r\n-----END PUBLIC KEY-----\r\n"
                );
            });

            it("fromString('84,97,116,252') should create a correct buffer", function () {
                const buf = CoreBuffer.fromString("84,97,116,252", Encoding.Csv);
                expect(buf.toArray()).to.have.members([84, 97, 116, 252]);
            });

            it("fromString('546174fc', 'hex') should create a correct buffer", function () {
                expect(CoreBuffer.fromString("546174fc", Encoding.Hex).toArray()).to.have.deep.members([
                    84, 97, 116, 252
                ]);
            });

            it("fromString('Tatü', 'latin1') should create a correct buffer", function () {
                expect(CoreBuffer.fromString("Tatü", Encoding.Latin1).toArray()).to.have.members([84, 97, 116, 252]);
            });

            it("fromString('Tat|', 'latin1') should create a correct buffer", function () {
                expect(CoreBuffer.fromString("Tat|", Encoding.Ascii).toArray()).to.have.members([84, 97, 116, 124]);
            });

            it("fromString('Tatü', 'ascii') should create a correct buffer", function () {
                expect(CoreBuffer.fromString("Tatü", Encoding.Ascii).toArray()).to.have.members([84, 97, 116, 252]);
            });

            it("fromString('Tat|', 'ascii') should create a correct buffer", function () {
                expect(CoreBuffer.fromString("Tat|", Encoding.Ascii).toArray()).to.have.members([84, 97, 116, 124]);
            });

            it("fromString('Tatü', 'utf8') should create a correct buffer", function () {
                expect(CoreBuffer.fromString("Tatü", Encoding.Utf8).toArray()).to.have.members([84, 97, 116, 195, 188]);
            });

            it("fromString('VGF0/A==', 'base64') should create a correct buffer", function () {
                expect(CoreBuffer.fromString("VGF0/A==", Encoding.Base64).toArray()).to.have.members([
                    84, 97, 116, 252
                ]);
            });

            it("fromString('VGF0w7w', 'base64') should create a correct buffer", function () {
                expect(CoreBuffer.fromString("VGF0w7w=", Encoding.Base64).toArray()).to.have.members([
                    84, 97, 116, 195, 188
                ]);
            });

            it("fromString(PEM, 'pem') should create a correct buffer (1)", function () {
                expect(
                    CoreBuffer.fromString(
                        "-----BEGIN PUBLIC KEY-----\r\nVGF0w7w=\r\n-----END PUBLIC KEY-----\r\n",
                        Encoding.Pem
                    ).toArray()
                ).to.have.members([84, 97, 116, 195, 188]);
            });

            it("fromString(PEM, 'pem', 'EC PRIVATE KEY') should create a correct buffer", function () {
                expect(
                    CoreBuffer.fromString(
                        "-----BEGIN EC PRIVATE KEY-----\r\nVGF0w7w=\r\n-----END EC PRIVATE KEY-----\r\n",
                        Encoding.Pem
                    ).toArray()
                ).to.have.members([84, 97, 116, 195, 188]);
            });

            it("fromString(PEM, 'pem') should create a correct buffer (2)", function () {
                expect(
                    CoreBuffer.fromString(
                        "-----BEGIN PUBLIC KEY-----\r\nVGF0w7xUYXTDvFRhdMO8VGF0w7xUYXTDvFRhdMO8VGF0w7xUYXTDvFRhdMO8VGF0\r\nw7xUYXTDvFRhdMO8VGF0w7xUYXTDvFRhdMO8VGF0w7xUYXTDvFRhdMO8\r\n-----END PUBLIC KEY-----\r\n",
                        Encoding.Pem
                    ).toArray()
                ).to.have.members([
                    84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84, 97,
                    116, 195, 188, 84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84, 97, 116,
                    195, 188, 84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84, 97, 116, 195,
                    188, 84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84, 97, 116, 195, 188, 84,
                    97, 116, 195, 188
                ]);
            });

            it("fromObject([84,97,116,252]) should create a correct buffer", function () {
                const buf = CoreBuffer.fromObject([84, 97, 116, 252]);
                expect(buf.toArray()).to.have.members([84, 97, 116, 252]);
            });

            it("fromObject(Uint8Array([84,97,116,252])) should create a correct buffer", function () {
                const a = new Uint8Array([84, 97, 116, 252]);
                const buf = CoreBuffer.fromObject(a);
                expect(buf.toArray()).to.have.members([84, 97, 116, 252]);
            });

            it("fromObject(ArrayBuffer([84,97,116,252])) should create a correct buffer", function () {
                const a = new Uint8Array([84, 97, 116, 252]);
                const ab = a.buffer;
                const buf = CoreBuffer.fromObject(ab);
                expect(buf.toArray()).to.have.members([84, 97, 116, 252]);
            });
        });
    }
}
