/* eslint-disable @typescript-eslint/naming-convention */
import { ISerializable, Serializable, type } from "@js-soft/ts-serval";
import { BaseX } from "./BaseX";
import { CryptoError } from "./CryptoError";
import { CryptoErrorCode } from "./CryptoErrorCode";
import { SodiumWrapper } from "./SodiumWrapper";

/**
 * Supported string encoding types.
 */
export enum Encoding {
    /** String is ASCII encoded, values 0-127 equal values 128-255 */
    Ascii = "ascii",
    /** String is Base64 encoded */
    Base64 = "base64",
    Base64_NoPadding = "base64_nopadding",
    /** String is Base64 encoded */
    Base64_UrlSafe_NoPadding = "base64_urlsafe_nopadding",
    /** String contains comma-separated decimal values (0-255) */
    Csv = "csv",
    /** String contains hexadecimal encoded-bytes AB => 171 */
    Hex = "hex",
    /** String is PEM encoded with Base64 buffer content and pre- and succeeding labels */
    Pem = "pem",
    /** String is Latin1 encoded */
    Latin1 = "latin1",
    /** String is UTF-8 encoded */
    Utf8 = "utf8"
}

export interface ICoreBuffer extends ISerializable, IClearable {
    /** The underlying native Buffer/Uint8Array object */
    readonly buffer: Uint8Array;
    readonly length: number;
    /**
     * Checks if the current buffer equals the given buffer
     *
     * @param compare The buffer to compare to
     */
    equals(compare: ICoreBuffer): boolean;
    toString(encoding: Encoding, label?: string): string;
    toBase64(): string;
    toBase64URL(): string;
    toUtf8(): string;
    toArray(): Number[];
    append(buffer: ICoreBuffer): void;
    prepend(buffer: ICoreBuffer): void;
}

export interface IClearable {
    clear(): void;
}

export interface ICoreBufferStatic {
    new (): ICoreBuffer;
    fromBase64(value: string): ICoreBuffer;
    fromUtf8(value: string): ICoreBuffer;
    fromString(value: string, encoding: Encoding): ICoreBuffer;
    fromObject(value: any): ICoreBuffer;
}

@type("CoreBuffer")
export class CoreBuffer extends Serializable implements ICoreBuffer {
    private _buffer: Uint8Array;

    public constructor(value: any = []) {
        super();

        if (value instanceof ArrayBuffer) {
            this._buffer = new Uint8Array(value, 0, value.byteLength);
        } else if (value instanceof Uint8Array) {
            this._buffer = value;
        } else if (value instanceof Array) {
            this._buffer = Uint8Array.from(value);
        } else if (value instanceof CoreBuffer) {
            this._buffer = value.buffer;
        } else if (typeof value === "string") {
            this._buffer = CoreBuffer.urlSafeBase64WithNoPaddingToBuffer(value).buffer;
        } else {
            throw new Error(
                `Value is of type object but not an Array/ArrayBuffer/Buffer or Uint8Array! Value: ${value}`
            );
        }
    }

    public get buffer(): Uint8Array {
        return this._buffer;
    }

    public get length(): number {
        return this._buffer.length;
    }

    public clone(): CoreBuffer {
        const clone = new Uint8Array(this.buffer);
        return new CoreBuffer(clone);
    }

    public equals(compare: ICoreBuffer): boolean {
        if (this.buffer.byteLength !== compare.buffer.byteLength) return false;
        for (let i = 0, l = this.buffer.byteLength; i < l; i++) {
            if (this.buffer[i] !== compare.buffer[i]) return false;
        }
        return true;
    }

    private bufferToCSV(): string {
        return Array.from(this._buffer).toString();
    }

    private bufferToLatin1(): string {
        return Array.prototype.map
            .call(this._buffer, function (byte: any) {
                return String.fromCharCode(byte);
            })
            .join("");
    }

    private bufferToHex(): string {
        return SodiumWrapper.sodium.to_hex(this._buffer);
    }

    private bufferToBase64(): string {
        const sodium = SodiumWrapper.sodium as any;
        return sodium.to_base64(this._buffer, sodium.base64_variants.ORIGINAL);
    }

    private bufferToBase64NoPadding(): string {
        const sodium = SodiumWrapper.sodium as any;
        return sodium.to_base64(this._buffer, sodium.base64_variants.ORIGINAL_NO_PADDING);
    }

    private bufferToBase64URL(): string {
        const sodium = SodiumWrapper.sodium as any;
        return sodium.to_base64(this._buffer, sodium.base64_variants.URLSAFE_NO_PADDING);
    }

    private bufferToAscii(): string {
        return Array.prototype.map
            .call(this._buffer, function (byte: any) {
                return String.fromCharCode(byte % 128);
            })
            .join("");
    }

    private bufferToUTF8(): string {
        return SodiumWrapper.sodium.to_string(this._buffer);
    }

    private bufferToPem(label?: string) {
        if (!label) label = "PUBLIC KEY";
        const base64Cert: string = this.bufferToBase64();
        let pemCert = `-----BEGIN ${label}-----\r\n`;
        let nextIndex = 0;
        while (nextIndex < base64Cert.length) {
            if (nextIndex + 64 <= base64Cert.length) {
                pemCert += `${base64Cert.substr(nextIndex, 64)}\r\n`;
            } else {
                pemCert += `${base64Cert.substr(nextIndex)}\r\n`;
            }
            nextIndex += 64;
        }
        pemCert += `-----END ${label}-----\r\n`;
        return pemCert;
    }

    public toBase64(): string {
        return this.toString(Encoding.Base64);
    }

    public toBase58(): string {
        const b58 = new BaseX("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
        return b58.encode(this);
    }

    public toBase64URL(): string {
        return this.toString(Encoding.Base64_UrlSafe_NoPadding);
    }

    public toUtf8(): string {
        return this.toString(Encoding.Utf8);
    }

    public clear(): this {
        SodiumWrapper.sodium.memzero(this.buffer);
        return this;
    }

    public override toString(encoding: Encoding = Encoding.Base64, label?: string): string {
        let str;
        switch (`${encoding}`.toLowerCase()) {
            case Encoding.Csv:
                str = this.bufferToCSV();
                break;
            case Encoding.Utf8:
                str = this.bufferToUTF8();
                break;
            case Encoding.Latin1:
                str = this.bufferToLatin1();
                break;
            case Encoding.Ascii:
                str = this.bufferToAscii();
                break;
            case Encoding.Hex:
                str = this.bufferToHex();
                break;
            case Encoding.Base64:
                str = this.bufferToBase64();
                break;
            case Encoding.Base64_NoPadding:
                str = this.bufferToBase64NoPadding();
                break;
            case Encoding.Base64_UrlSafe_NoPadding:
                str = this.bufferToBase64URL();
                break;
            case Encoding.Pem:
                str = this.bufferToPem(label);
                break;
            default:
                throw new Error(`Encoding ${encoding} not supported.`);
        }
        return str;
    }

    public toArray(): number[] {
        return Array.from(this._buffer);
    }

    public append(buffer: ICoreBuffer): this {
        const tmp = new Uint8Array(this._buffer.byteLength + buffer.buffer.byteLength);
        tmp.set(new Uint8Array(this._buffer), 0);
        tmp.set(new Uint8Array(buffer.buffer), this._buffer.byteLength);
        this._buffer = tmp;
        return this;
    }

    public prepend(buffer: ICoreBuffer): this {
        const tmp = new Uint8Array(this._buffer.byteLength + buffer.buffer.byteLength);
        tmp.set(new Uint8Array(buffer.buffer), 0);
        tmp.set(new Uint8Array(this._buffer), buffer.buffer.byteLength);
        this._buffer = tmp;
        return this;
    }

    public override toJSON(): Object {
        return this.serialize();
    }

    public override serialize(): string {
        return this.toBase64URL();
    }

    public add(value: number): this {
        // Create a 4*8-bit representation out of the 64bit "float"
        const intBuffer = new Uint32Array([value]);
        const counterBuffer = new Uint8Array(intBuffer.buffer);

        // Create a n*8-bit representation, fill it with the 8*8-bit in order to add it to the actual nonce
        const counterBufferCorrectLength = new Uint8Array(this.buffer.byteLength);
        counterBufferCorrectLength.set(counterBuffer, this.buffer.byteLength - counterBuffer.byteLength);

        const sum = this.buffer;
        try {
            // Sum up both arrays
            SodiumWrapper.sodium.add(sum, counterBufferCorrectLength);
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.BufferAdd, `${e}`);
        } finally {
            intBuffer.fill(0);
            counterBuffer.fill(0);
            counterBufferCorrectLength.fill(0);
        }

        return this;
    }

    public static fromBase58(value: string): CoreBuffer {
        const b58 = new BaseX("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
        return b58.decode(value);
    }

    public static from(value: any): CoreBuffer {
        return this.fromAny(value);
    }

    private static hexToBuffer(hex: string): CoreBuffer {
        const result = SodiumWrapper.sodium.from_hex(hex);
        return new CoreBuffer(result);
    }

    private static latin1ToBuffer(str: string): CoreBuffer {
        const buf = new Uint8Array(str.length);
        for (let i = 0, strLen = str.length; i < strLen; i++) {
            buf[i] = str.charCodeAt(i);
        }
        return new CoreBuffer(buf);
    }

    private static asciiToBuffer(str: string): CoreBuffer {
        const buf = new Uint8Array(str.length);
        for (let i = 0, strLen = str.length; i < strLen; i++) {
            buf[i] = str.charCodeAt(i);
        }
        return new CoreBuffer(buf);
    }

    private static base64ToBuffer(base64: string): CoreBuffer {
        const sodium = SodiumWrapper.sodium as any;
        const binary = sodium.from_base64(base64, sodium.base64_variants.ORIGINAL);
        return new CoreBuffer(binary);
    }

    private static base64NoPaddingToBuffer(base64: string): CoreBuffer {
        const sodium = SodiumWrapper.sodium as any;
        const binary = sodium.from_base64(base64, sodium.base64_variants.ORIGINAL_NO_PADDING);
        return new CoreBuffer(binary);
    }

    private static urlSafeBase64WithNoPaddingToBuffer(base64: string): CoreBuffer {
        const sodium = SodiumWrapper.sodium as any;
        const binary = sodium.from_base64(base64, sodium.base64_variants.URLSAFE_NO_PADDING);
        return new CoreBuffer(binary);
    }

    private static utf8ToBuffer(utf8: string): CoreBuffer {
        return new CoreBuffer(SodiumWrapper.sodium.from_string(utf8));
    }

    private static pemToBuffer(pem: string): CoreBuffer {
        pem = pem.replace(/-----BEGIN [\w ]* KEY-----/, "");
        pem = pem.replace(/-----END [\w ]* KEY-----/, "");
        pem = pem.replace(/----- BEGIN [\w ]* KEY -----/, "");
        pem = pem.replace(/----- END [\w ]* KEY -----/, "");
        pem = pem.replace(/(?:\r\n|\r|\n)/g, "");
        return this.base64ToBuffer(pem);
    }

    public static fromBase64(value: string): CoreBuffer {
        return this.fromString(value, Encoding.Base64);
    }

    public static fromBase64URL(value: string): CoreBuffer {
        return this.fromString(value, Encoding.Base64_UrlSafe_NoPadding);
    }

    public static fromUtf8(value: string): CoreBuffer {
        return this.fromString(value, Encoding.Utf8);
    }

    public static fromString(value: string, encoding: Encoding): CoreBuffer {
        let buffer: CoreBuffer;
        if (typeof value === "string") {
            switch (`${encoding}`.toLowerCase()) {
                case Encoding.Csv:
                    const strbuf: string[] = `${value}`.split(",");
                    const str: string[] = [];
                    for (let i = 0, strLen = strbuf.length; i < strLen; i++) {
                        str.push(String.fromCharCode(parseInt(strbuf[i])));
                    }
                    buffer = this.latin1ToBuffer(str.join(""));
                    break;
                case Encoding.Latin1:
                    buffer = this.latin1ToBuffer(value);
                    break;
                case Encoding.Ascii:
                    buffer = this.asciiToBuffer(value);
                    break;
                case Encoding.Utf8:
                    buffer = this.utf8ToBuffer(value);
                    break;
                case Encoding.Hex:
                    buffer = this.hexToBuffer(value);
                    break;
                case Encoding.Base64:
                    buffer = this.base64ToBuffer(value);
                    break;
                case Encoding.Base64_NoPadding:
                    buffer = this.base64NoPaddingToBuffer(value);
                    break;
                case Encoding.Base64_UrlSafe_NoPadding:
                    buffer = this.urlSafeBase64WithNoPaddingToBuffer(value);
                    break;
                case Encoding.Pem:
                    buffer = this.pemToBuffer(value);
                    break;
                default:
                    throw new Error(`Encoding ${encoding} not supported.`);
            }
            return buffer;
        }
        throw new Error("Value is not of type string!");
    }

    public static base64_json(value: string): Object {
        return JSON.parse(this.base64_utf8(value));
    }

    public static json_base64(value: Object): string {
        return this.utf8_base64(JSON.stringify(value));
    }

    public static utf8_base64(value: string): string {
        return CoreBuffer.fromUtf8(value).toBase64URL();
    }

    public static base64_utf8(value: string): string {
        return CoreBuffer.fromBase64URL(value).toUtf8();
    }

    public static fromObject(value: any): CoreBuffer {
        return new CoreBuffer(value);
    }

    public static random(length: number): CoreBuffer {
        const sodium = SodiumWrapper.sodium as any;
        return new CoreBuffer(sodium.randombytes_buf(length));
    }
}
