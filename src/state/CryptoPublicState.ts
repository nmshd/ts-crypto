import { ISerializable, ISerialized, Serializable, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../CoreBuffer";
import { CryptoValidation } from "../CryptoValidation";
import { CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { CryptoStateType } from "./CryptoStateType";

export interface ICryptoPublicStateSerialized extends ISerialized {
    nnc: string;
    alg: number;
    id?: string;
    typ: number;
}

export interface ICryptoPublicState extends ISerializable {
    nonce: CoreBuffer;
    algorithm: CryptoEncryptionAlgorithm;
    id?: string;
    stateType: CryptoStateType;
}

@type("CryptoPublicState")
export class CryptoPublicState extends Serializable implements ICryptoPublicState, IClearable {
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    @validate()
    @serialize()
    public nonce: CoreBuffer;

    @validate()
    @serialize()
    public algorithm: CryptoEncryptionAlgorithm;

    @validate()
    @serialize()
    public stateType: CryptoStateType;

    public clear(): void {
        this.nonce.clear();
    }

    public override toJSON(verbose = true): ICryptoPublicStateSerialized {
        return {
            "@type": verbose ? "CryptoPublicState" : undefined,
            nnc: this.nonce.toBase64URL(),
            alg: this.algorithm,
            typ: this.stateType,
            id: this.id
        };
    }

    protected static override preFrom(value: any): any {
        if (value.nnc) {
            value = {
                nonce: value.nnc,
                algorithm: value.alg,
                stateType: value.typ,
                id: value.id
            };
        }

        CryptoValidation.checkEncryptionAlgorithm(value.algorithm);
        CryptoValidation.checkStateType(value.stateType);
        CryptoValidation.checkNonce(value.nonce, value.algorithm);

        return value;
    }

    public static from(value: CryptoPublicState | ICryptoPublicState): CryptoPublicState {
        return this.fromAny(value);
    }

    public static fromJSON(value: ICryptoPublicStateSerialized): CryptoPublicState {
        return this.fromAny(value);
    }

    public static fromBase64(value: string): CryptoPublicState {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}
