import { ISerializable, ISerialized, Serializable, serialize, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoSecretKeyHandle } from "../crypto-layer/encryption/CryptoSecretKeyHandle";
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
    secretKey: CoreBuffer | CryptoSecretKeyHandle;
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
    public secretKey: CoreBuffer | CryptoSecretKeyHandle;

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
        if (this.secretKey instanceof CoreBuffer) {
            this.secretKey.clear();
        }
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

    /**
     * Determines if this state is using the crypto-layer implementation
     * @returns True if using CAL, false if using libsodium
     */
    public isUsingCryptoLayer(): boolean {
        return this.secretKey instanceof CryptoSecretKeyHandle;
    }

    public override async toJSON(verbose = true): Promise<ICryptoPrivateStateSerialized> {
        let keyValue: string;
        if (this.secretKey instanceof CryptoSecretKeyHandle) {
            keyValue = await this.secretKey.toSerializedString();
        } else {
            keyValue = this.secretKey.toBase64URL();
        }

        return {
            nnc: this.nonce.toBase64URL(),
            cnt: this.counter,
            key: keyValue,
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

        // Only validate secretKey if it's not a handle
        if (!(value.secretKey instanceof CryptoSecretKeyHandle)) {
            CryptoValidation.checkSecretKeyForAlgorithm(value.secretKey, value.algorithm);
        }

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

export function isCryptoPrivateState(obj: any): obj is CryptoPrivateState {
    return obj instanceof CryptoPrivateState;
}
