import { ISerializableAsync, SerializableAsync, type } from "@js-soft/ts-serval";
import { CryptoStreamAddress } from "./CryptoStreamAddress";
import { CryptoStreamHeader } from "./CryptoStreamHeader";

export interface ICryptoStreamState extends ISerializableAsync {
    address: CryptoStreamAddress;
    header: CryptoStreamHeader;
}

export interface ICryptoStreamaddressStatic {
    new (): CryptoStreamState;
    from(obj: ICryptoStreamState): Promise<ICryptoStreamState>;
    deserialize(content: string): Promise<ICryptoStreamState>;
}

@type("CryptoStreamState")
export class CryptoStreamState extends SerializableAsync implements ICryptoStreamState {
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

    public static async from(obj: any): Promise<CryptoStreamState> {
        if (!obj.address || !obj.header) {
            throw new Error("No address or header property set.");
        }

        const address = await CryptoStreamAddress.from({ address: obj.address });
        const header = await CryptoStreamHeader.fromBase64(obj.header);
        return new CryptoStreamState(address, header);
    }

    public static async deserialize(value: string): Promise<CryptoStreamState> {
        const obj = JSON.parse(value);
        return await this.from(obj);
    }
}
