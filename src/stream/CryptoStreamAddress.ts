import { ISerializableAsync, SerializableAsync, type } from "@js-soft/ts-serval";

export interface ICryptoStreamAddress extends ISerializableAsync {
    readonly address: string;
    toString(): string;
    serialize(): string;
}

export interface ICryptoStreamAddressStatic {
    new (): ICryptoStreamAddress;
    from(obj: ICryptoStreamAddress): Promise<ICryptoStreamAddress>;
    deserialize(content: string): Promise<ICryptoStreamAddress>;
}

@type("CryptoStreamAddress")
export class CryptoStreamAddress extends SerializableAsync implements ICryptoStreamAddress {
    public readonly address: string;

    public constructor(address: string) {
        super();
        this.address = address;
    }

    public toString(): string {
        return this.serialize();
    }

    public serialize(): string {
        const obj = this.toJSON();
        return JSON.stringify(obj);
    }

    public toJSON(): Object {
        const obj = {
            "@type": "CryptoStreamAddress",
            address: this.address
        };
        return obj;
    }

    public static from(obj: any | string): Promise<CryptoStreamAddress> {
        if (typeof obj === "string") {
            return Promise.resolve(new CryptoStreamAddress(obj));
        }
        if (!obj.address) {
            throw new Error("No address property set.");
        }

        return Promise.resolve(new CryptoStreamAddress(obj.address));
    }

    public static async deserialize(value: string): Promise<CryptoStreamAddress> {
        const obj = JSON.parse(value);
        return await this.from(obj);
    }
}
