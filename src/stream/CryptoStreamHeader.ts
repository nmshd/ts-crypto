import { ISerializableAsync, SerializableAsync, type } from "@js-soft/ts-serval";
import { CoreBuffer, ICoreBuffer } from "../CoreBuffer";

export interface ICryptoStreamHeader extends ISerializableAsync {
    readonly header: ICoreBuffer;
    toString(): string;
    serialize(): string;
}

export interface ICryptoStreamHeaderStatic {
    new (): ICryptoStreamHeader;
    from(obj: ICryptoStreamHeader): Promise<ICryptoStreamHeader>;
    deserialize(content: string): Promise<ICryptoStreamHeader>;
}

@type("CryptoStreamHeader")
export class CryptoStreamHeader extends SerializableAsync implements ICryptoStreamHeader {
    public readonly header: ICoreBuffer;

    public constructor(header: ICoreBuffer) {
        super();

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
            "@type": "CryptoStreamHeader",
            header: this.header.toBase64()
        };
        return obj;
    }

    public toBase64(): string {
        return this.header.toBase64();
    }

    public static from(obj: any): Promise<CryptoStreamHeader> {
        if (!obj.header) {
            throw new Error("No state or header property set.");
        }

        const header = CoreBuffer.fromBase64(obj.header);
        return Promise.resolve(new CryptoStreamHeader(header));
    }

    public static deserialize(value: string): Promise<CryptoStreamHeader> {
        const obj = JSON.parse(value);
        return Promise.resolve(this.from(obj));
    }

    public static fromBase64(value: string): Promise<CryptoStreamHeader> {
        const buffer = CoreBuffer.fromBase64(value);
        return Promise.resolve(new CryptoStreamHeader(buffer));
    }
}
