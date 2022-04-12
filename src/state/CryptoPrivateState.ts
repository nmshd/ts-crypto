import { ISerializable, ISerialized, Serializable, serialize, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoValidation } from "../CryptoValidation";
import { CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { CryptoPublicState } from "./CryptoPublicState";
import { CryptoStateType } from "./CryptoStateType";

export interface ICryptoPrivateStateSerialized extends ISerialized {
    key: string;
    nnc: string;
    cnt: number;
    alg: number;
    id?: string;
    typ: number;
}

export interface ICryptoPrivateState extends ISerializable {
    secretKey: ICoreBuffer;
    nonce: ICoreBuffer;
    counter: number;
    algorithm: CryptoEncryptionAlgorithm;
    id?: string;
    stateType: CryptoStateType;
}

export class CryptoPrivateState extends Serializable implements ICryptoPrivateState, IClearable {
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    @validate()
    @serialize()
    public nonce: CoreBuffer;

    @validate()
    @serialize()
    public counter: number;

    @validate()
    @serialize()
    public secretKey: CoreBuffer;

    @validate()
    @serialize()
    public algorithm: CryptoEncryptionAlgorithm;

    @validate()
    @serialize()
    public stateType: CryptoStateType;

    protected setCounter(value: number): void {
        this.counter = value;
    }

    public clear(): void {
        this.secretKey.clear();
        this.nonce.clear();
    }

    public override toString(): string {
        return this.serialize();
    }

    public toPublicState(): CryptoPublicState {
        return CryptoPublicState.from({
            nonce: this.nonce.clone(),
            algorithm: this.algorithm,
            stateType: this.stateType,
            id: this.id
        });
    }

    public override toJSON(verbose = true): ICryptoPrivateStateSerialized {
        return {
            nnc: this.nonce.toBase64URL(),
            cnt: this.counter,
            key: this.secretKey.toBase64URL(),
            alg: this.algorithm,
            typ: this.stateType,
            id: this.id,
            "@type": verbose ? "CryptoPrivateState" : undefined
        };
    }

    protected static override preFrom(value: any): any {
        if (value.nnc) {
            value = {
                nonce: value.nnc,
                counter: value.cnt,
                secretKey: value.key,
                algorithm: value.alg,
                stateType: value.typ,
                id: value.id
            };
        }

        CryptoValidation.checkEncryptionAlgorithm(value.algorithm);
        CryptoValidation.checkCounter(value.counter);
        CryptoValidation.checkNonce(value.nonce, value.algorithm);
        CryptoValidation.checkSecretKeyForAlgorithm(value.secretKey, value.algorithm);
        CryptoValidation.checkStateType(value.stateType);

        if (value.id) {
            CryptoValidation.checkId(value.id);
        }

        return value;
    }

    public static from(obj: CryptoPrivateState | ICryptoPrivateState): CryptoPrivateState {
        return this.fromAny(obj);
    }

    public static fromJSON(value: ICryptoPrivateStateSerialized): CryptoPrivateState {
        return this.fromAny(value);
    }
}
