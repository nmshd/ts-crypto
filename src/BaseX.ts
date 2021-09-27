import { CoreBuffer } from "./CoreBuffer";

// Encoding / decoding of base-x
// Copyright (c) 2018 base-x contributors
// Copyright (c) 2014-2018 The Bitcoin Core developers (base58.cpp)
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
export class BaseX {
    public constructor(alphabet: string) {
        this.initializeAlphabet(alphabet);
    }

    private alphabet: string;
    private baseMap: Uint8Array;
    private base: number;
    private leader: string;
    private factor: number;
    private iFactor: number;

    private initializeAlphabet(alphabet: string) {
        if (alphabet.length >= 255) {
            throw new TypeError("Alphabet too long");
        }
        this.baseMap = new Uint8Array(256);
        for (let j = 0, l = this.baseMap.length; j < l; j++) {
            this.baseMap[j] = 255;
        }
        for (let i = 0, l = alphabet.length; i < l; i++) {
            const x = alphabet.charAt(i);
            const xc = x.charCodeAt(0);
            if (this.baseMap[xc] !== 255) {
                throw new TypeError(`${x} is ambiguous`);
            }
            this.baseMap[xc] = i;
        }
        this.alphabet = alphabet;
        this.base = alphabet.length;
        this.leader = alphabet.charAt(0);
        this.factor = Math.log(this.base) / Math.log(256); // The result is being rounded up
        this.iFactor = Math.log(256) / Math.log(this.base); // The result is being rounded up
    }

    public encode(source: CoreBuffer): string {
        if (source.length === 0) {
            return "";
        }
        // Skip & count leading zeroes.
        let zeroes = 0;
        let length = 0;
        let pbegin = 0;
        const pend = source.length;
        while (pbegin !== pend && source.buffer[pbegin] === 0) {
            pbegin++;
            zeroes++;
        }
        // Allocate enough space in big-endian base58 representation.
        const size = ((pend - pbegin) * this.iFactor + 1) >>> 0;
        const b58 = new Uint8Array(size);
        // Process the bytes.
        while (pbegin !== pend) {
            let carry = source.buffer[pbegin];
            // Apply "b58 = b58 * 256 + ch".
            let i = 0;
            for (let it1 = size - 1; (carry !== 0 || i < length) && it1 !== -1; it1--, i++) {
                carry += (256 * b58[it1]) >>> 0;
                b58[it1] = carry % this.base >>> 0;
                carry = (carry / this.base) >>> 0;
            }
            if (carry !== 0) {
                throw new Error("Non-zero carry");
            }
            length = i;
            pbegin++;
        }
        // Skip leading zeroes in base58 result.
        let it2 = size - length;
        while (it2 !== size && b58[it2] === 0) {
            it2++;
        }
        // Translate the result into a string.
        let str = this.leader.repeat(zeroes);
        for (; it2 < size; ++it2) {
            str += this.alphabet.charAt(b58[it2]);
        }
        return str;
    }
    public decode(source: string): CoreBuffer {
        if (typeof source !== "string") {
            throw new TypeError("Expected String");
        }
        if (source.length === 0) {
            return new CoreBuffer();
        }
        let psz = 0;
        // Skip leading spaces.
        if (source[psz] === " ") {
            throw new TypeError("Invalid input.");
        }
        // Skip and count leading '1's.
        let zeroes = 0;
        let length = 0;
        while (source[psz] === this.leader) {
            zeroes++;
            psz++;
        }
        // Allocate enough space in big-endian base256 representation.
        const size = ((source.length - psz) * this.factor + 1) >>> 0; // The result is being rounded up.
        const b256 = new Uint8Array(size);
        // Process the characters.
        while (source[psz]) {
            // Decode character
            let carry = this.baseMap[source.charCodeAt(psz)];
            // Invalid character
            if (carry === 255) {
                throw new TypeError("Invalid input.");
            }
            let i = 0;
            for (let it3 = size - 1; (carry !== 0 || i < length) && it3 !== -1; it3--, i++) {
                carry += (this.base * b256[it3]) >>> 0;
                b256[it3] = carry % 256 >>> 0;
                carry = (carry / 256) >>> 0;
            }
            if (carry !== 0) {
                throw new Error("Non-zero carry");
            }
            length = i;
            psz++;
        }
        // Skip trailing spaces.
        if (source[psz] === " ") {
            throw new TypeError("Invalid input.");
        }
        // Skip leading zeroes in b256.
        let it4 = size - length;
        while (it4 !== size && b256[it4] === 0) {
            it4++;
        }

        const vch = new Uint8Array(zeroes + (size - it4));
        vch.fill(0x00, 0, zeroes);
        let j = zeroes;
        while (it4 !== size) {
            vch[j++] = b256[it4++];
        }
        return new CoreBuffer(vch);
    }
}
