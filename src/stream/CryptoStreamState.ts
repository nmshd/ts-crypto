import { ISerializable, Serializable, type } from "@js-soft/ts-serval";
import { CryptoStreamAddress } from "./CryptoStreamAddress";
import { CryptoStreamHeader } from "./CryptoStreamHeader";

export interface ICryptoStreamState extends ISerializable {
    address: CryptoStreamAddress;
    header: CryptoStreamHeader;
}

export interface ICryptoStreamaddressStatic {
    new (): CryptoStreamState;
    from(obj: ICryptoStreamState): Promise<ICryptoStreamState>;
    deserialize(content: string): Promise<ICryptoStreamState>;
}

@type("CryptoStreamState")
export class CryptoStreamState extends Serializable implements ICryptoStreamState {
    public readonly address: CryptoStreamAddress;
    public readonly header: CryptoStreamHeader;

    public constructor(address: CryptoStreamAddress, header: CryptoStreamHeader) {
        super();

        this.address = address;
        this.header = header;
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
            "@type": "CryptoStreamState",
            address: this.address.address,
            header: this.header.toBase64()
        };
        return obj;
    }

    public static from(obj: any): CryptoStreamState {
        if (!obj.address || !obj.header) {
            throw new Error("No address or header property set.");
        }

        const address = CryptoStreamAddress.from({ address: obj.address });
        const header = CryptoStreamHeader.fromBase64(obj.header);
        return new CryptoStreamState(address, header);
    }

    public static deserialize(value: string): CryptoStreamState {
        const obj = JSON.parse(value);
        return this.from(obj);
    }
}
