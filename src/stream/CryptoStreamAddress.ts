import { ISerializable, Serializable, serialize, type, validate } from "@js-soft/ts-serval";

export interface ICryptoStreamAddress extends ISerializable {
    address: string;
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
    @validate()
    @serialize()
    public address: string;

    public override toString(): string {
        return this.serialize();
    }

    protected static override preFrom(obj: any): any {
        if (typeof obj === "string") {
            return { address: obj };
        }

        return obj;
    }

    public static from(obj: any | string): CryptoStreamAddress {
        return this.fromAny(obj);
    }
}
