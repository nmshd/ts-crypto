import { v4 as uuidv4 } from "uuid";
import { CoreBuffer } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { SodiumWrapper } from "../SodiumWrapper";

export enum CryptoRandomCharacterRange {
    Digit = "0123456789",
    DigitEase = "123456789",
    Hex = "0123456789ABCDEF",
    LowerCase = "abcdefghijklmnopqrstuvwxyz",
    LowerCaseEase = "abcdefghijkmnpqrstuvwxyz",
    UpperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    UpperCaseEase = "ABCDEFGHJKLMNPQRSTUVWXYZ",
    Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    Alphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    // Without I, l, O, o, 0
    AlphanumericEase = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789",
    AlphanumericUpperCaseEase = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789",
    GermanUmlaut = "ÄÖÜäöü",
    SpecialCharacters = "!?-_.:,;#+"
}

export interface CryptoRandomCharacterBucket {
    minLength: number;
    maxLength: number;
    allowedChars: string | string[];
}

export class CryptoRandom {
    public static async bytes(length: number): Promise<CoreBuffer> {
        const useLength = Math.floor(length);
        if (useLength <= 0) {
            throw new CryptoError(
                CryptoErrorCode.WrongLength,
                "The length of the created random buffer must be positive."
            );
        }

        const randomBytes = (await SodiumWrapper.ready()).randombytes_buf(useLength);
        return new CoreBuffer(randomBytes);
    }
    public static async int(length: number): Promise<number> {
        const useLength = Math.floor(length);
        if (useLength > 21 || useLength <= 0) {
            throw new CryptoError(
                CryptoErrorCode.WrongLength,
                "The length of the created random buffer must be positive and smaller than 22 digits."
            );
        }
        return parseInt(await this.string(length, CryptoRandomCharacterRange.Digit));
    }
    public static async array(length: number): Promise<any> {
        return (await CryptoRandom.bytes(length)).toArray();
    }

    public static uuid(): string {
        return uuidv4();
    }

    public static async scramble(input: string): Promise<string> {
        const out = [];
        const inar = input.split("");
        const length = input.length;
        for (let i = 0; i < length - 1; i++) {
            const charAt = await CryptoRandom.intBetween(0, length - 1 - i);
            out.push(inar.splice(charAt, 1)[0]);
        }
        out.push(inar[0]);
        return out.join("");
    }

    public static async intBetween(min: number, max: number): Promise<number> {
        if (max <= min) throw new CryptoError(CryptoErrorCode.WrongParameters, "Max must be larger than min.");
        const diff = max - min + 1;
        const bitLength = Math.abs(Math.ceil(Math.log2(diff)));
        if (bitLength > 32) {
            throw new CryptoError(
                CryptoErrorCode.WrongParameters,
                "The range between the numbers is too big, 32 bit is the maximum -> 4294967296"
            );
        }
        const byteLength = Math.ceil(bitLength / 8);
        const bitMask = Math.pow(2, bitLength) - 1;
        const randomArray = await this.bytes(byteLength);

        let value = 0;
        let p = (byteLength - 1) * 8;
        for (let i = 0; i < byteLength; i++) {
            value += randomArray.buffer[i] * Math.pow(2, p);
            p -= 8;
        }
        value = value & bitMask;
        if (value >= diff) {
            return await this.intBetween(min, max);
        }
        return min + value;
    }

    public static async intRandomLength(minLength: number, maxLength: number): Promise<number> {
        if (maxLength > 21) {
            throw new CryptoError(
                CryptoErrorCode.WrongLength,
                "The length of the created random buffer must be positive and smaller than 22 digits."
            );
        }
        return parseInt(await this.stringRandomLength(minLength, maxLength, CryptoRandomCharacterRange.Digit));
    }

    public static async scrambleWithBuckets(buckets: CryptoRandomCharacterBucket[]): Promise<string> {
        const mystr = await this.stringWithBuckets(buckets);
        return await this.scramble(mystr);
    }

    public static async stringWithBuckets(buckets: CryptoRandomCharacterBucket[]): Promise<string> {
        const mystr = [];
        for (const bucket of buckets) {
            mystr.push(await this.stringRandomLength(bucket.minLength, bucket.maxLength, bucket.allowedChars));
        }
        return mystr.join("");
    }

    public static async string(
        length: number,
        allowedChars: string | string[] = CryptoRandomCharacterRange.Alphanumeric
    ): Promise<string> {
        if (length <= 0) return "";
        if (allowedChars.length > 255) {
            throw new CryptoError(
                CryptoErrorCode.WrongParameters,
                "The allowedCharacter array must not be larger than 255 characters."
            );
        }
        const ar = [];
        const inputLength = allowedChars.length;
        const random = await this.array(length + 10);
        const max = 255 - (255 % inputLength);
        for (let i = 0; i < length; i++) {
            const nmb = random[i];
            if (nmb > max) {
                // Reject random value to remove bias if we are at the upper (and incomplete end)
                // of possible random values
                continue;
            }
            ar.push(allowedChars[nmb % inputLength]);
        }
        let retStr = ar.join("");
        if (retStr.length < length) {
            retStr += await this.string(length - retStr.length, allowedChars);
        }
        return retStr;
    }
    public static async stringRandomLength(
        minLength: number,
        maxLength: number,
        allowedChars?: string | string[]
    ): Promise<string> {
        if (minLength > maxLength) {
            throw new CryptoError(CryptoErrorCode.WrongParameters, "Max must be larger than min.");
        }
        if (minLength < 0) throw new CryptoError(CryptoErrorCode.WrongParameters, "Min must be positive.");

        const length = maxLength > minLength ? await this.intBetween(minLength, maxLength) : maxLength;
        return await this.string(length, allowedChars);
    }
}
