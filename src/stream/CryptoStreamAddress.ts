import { ISerializable, Serializable, type } from "@js-soft/ts-serval";

export interface ICryptoStreamAddress extends ISerializable {
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
export class CryptoStreamAddress extends Serializable implements ICryptoStreamAddress {
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

    public static from(obj: any | string): CryptoStreamAddress {
        if (typeof obj === "string") {
            return new CryptoStreamAddress(obj);
        }
        if (!obj.address) {
            throw new Error("No address property set.");
        }

        return new CryptoStreamAddress(obj.address);
    }

    public static deserialize(value: string): CryptoStreamAddress {
        const obj = JSON.parse(value);
        return this.from(obj);
    }
}
