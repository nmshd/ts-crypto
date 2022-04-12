import { ISerializable, Serializable, serialize, type, validate } from "@js-soft/ts-serval";
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
    @validate()
    @serialize()
    public address: CryptoStreamAddress;

    @validate()
    @serialize()
    public header: CryptoStreamHeader;

    public override toString(): string {
        return this.serialize();
    }

    public static from(obj: ICryptoStreamState): CryptoStreamState {
        return this.fromAny(obj);
    }
}
