import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../CoreBuffer";
import {
    CryptoExchangePublicKeyHandle,
    ICryptoExchangePublicKeyHandleSerialized
} from "../crypto-layer/exchange/CryptoExchangePublicKeyHandle";
import { CryptoRelationshipPublicResponseHandle } from "../crypto-layer/relationship/CryptoRelationshipPublicResponseHandle";
import {
    CryptoSignaturePublicKeyHandle,
    ICryptoSignaturePublicKeyHandleSerialized
} from "../crypto-layer/signature/CryptoSignaturePublicKeyHandle";
import {
    CryptoPublicStateHandle,
    ICryptoPublicStateHandleSerialized
} from "../crypto-layer/state/CryptoPublicStateHandle";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoSerializable } from "../CryptoSerializable";
import { CryptoExchangePublicKey, ICryptoExchangePublicKeySerialized } from "../exchange/CryptoExchangePublicKey";
import { CryptoSignature } from "../signature/CryptoSignature";
import { CryptoSignaturePublicKey, ICryptoSignaturePublicKeySerialized } from "../signature/CryptoSignaturePublicKey";
import { CryptoSignatures } from "../signature/CryptoSignatures";
import { CryptoPublicState, ICryptoPublicStateSerialized } from "../state/CryptoPublicState";

export interface ICryptoRelationshipPublicResponseSerialized extends ISerialized {
    id?: string;
    exc: ICryptoExchangePublicKeyHandleSerialized | ICryptoExchangePublicKeySerialized;
    sig: ICryptoSignaturePublicKeyHandleSerialized | ICryptoSignaturePublicKeySerialized;
    sta: ICryptoPublicStateHandleSerialized | ICryptoPublicStateSerialized;
}

export interface ICryptoRelationshipPublicResponse extends ISerializable {
    id?: string;
    exchangeKey: CryptoExchangePublicKey | CryptoExchangePublicKeyHandle;
    signatureKey: CryptoSignaturePublicKey | CryptoSignaturePublicKeyHandle;
    state: CryptoPublicState | CryptoPublicStateHandle;
}

@type("CryptoRelationshipPublicResponse")
export class CryptoRelationshipPublicResponse
    extends CryptoSerializable
    implements ICryptoRelationshipPublicResponse, IClearable
{
    @validate({ nullable: true })
    @serialize()
    public id?: string;

    @validate()
    @serialize()
    public signatureKey: CryptoSignaturePublicKey | CryptoSignaturePublicKeyHandle;

    @validate()
    @serialize()
    public exchangeKey: CryptoExchangePublicKey | CryptoExchangePublicKeyHandle;

    @validate()
    @serialize()
    public state: CryptoPublicState | CryptoPublicStateHandle;

    public override toJSON(verbose = true): ICryptoRelationshipPublicResponseSerialized {
        return {
            exc: this.exchangeKey.toJSON(false),
            sig: this.signatureKey.toJSON(false),
            sta: this.state.toJSON(false),
            id: this.id,
            "@type": verbose ? "CryptoRelationshipPublicResponse" : undefined
        };
    }

    public clear(): void {
        if (this.exchangeKey instanceof CryptoExchangePublicKey) {
            this.exchangeKey.clear();
        }
        if (this.signatureKey instanceof CryptoSignaturePublicKey) {
            this.signatureKey.clear();
        }
        if (this.state instanceof CryptoPublicState) {
            this.state.clear();
        }
    }

    /**
     * Determines if this response is using the crypto-layer implementation
     * @returns True if using CAL, false if using libsodium
     */
    public isUsingCryptoLayer(): boolean {
        return (
            this.exchangeKey instanceof CryptoExchangePublicKeyHandle &&
            this.signatureKey instanceof CryptoSignaturePublicKeyHandle &&
            this.state instanceof CryptoPublicStateHandle
        );
    }

    /**
     * Verifies content with the signature key included in this response
     * @param content Content to verify
     * @param signature Signature to verify
     * @returns Promise resolving to true if verified, false otherwise
     */
    public async verify(content: CoreBuffer, signature: CryptoSignature): Promise<boolean> {
        return await CryptoSignatures.verify(content, signature, this.signatureKey);
    }

    /**
     * Converts this response to a CAL handle
     * @returns A promise resolving to a CAL response handle
     */
    public async toHandle(): Promise<CryptoRelationshipPublicResponseHandle> {
        // If we're already using CAL-compatible components
        if (
            this.exchangeKey instanceof CryptoExchangePublicKeyHandle &&
            this.signatureKey instanceof CryptoSignaturePublicKeyHandle &&
            this.state instanceof CryptoPublicStateHandle
        ) {
            return await CryptoRelationshipPublicResponseHandle.from({
                id: this.id,
                exchangeKey: this.exchangeKey,
                signatureKey: this.signatureKey,
                state: this.state
            });
        }

        // If state is a CryptoPublicState, convert it to a handle
        if (!(this.state instanceof CryptoPublicStateHandle)) {
            try {
                const stateHandle = await this.state.toHandle();

                // If keys are also handles, create a response handle
                if (
                    this.exchangeKey instanceof CryptoExchangePublicKeyHandle &&
                    this.signatureKey instanceof CryptoSignaturePublicKeyHandle
                ) {
                    return await CryptoRelationshipPublicResponseHandle.from({
                        id: this.id,
                        exchangeKey: this.exchangeKey,
                        signatureKey: this.signatureKey,
                        state: stateHandle
                    });
                }
            } catch (e) {
                // Fall through to error
            }
        }

        throw new CryptoError(
            CryptoErrorCode.CalUninitializedKey,
            "Cannot create handle: this response doesn't use crypto-layer handles"
        );
    }

    public static from(
        value: CryptoRelationshipPublicResponse | ICryptoRelationshipPublicResponse
    ): CryptoRelationshipPublicResponse {
        return this.fromAny(value);
    }

    protected static override preFrom(value: any): any {
        if (value.exc) {
            value = {
                exchangeKey: value.exc,
                signatureKey: value.sig,
                state: value.sta,
                id: value.id
            };
        }

        return value;
    }

    public static fromJSON(value: ICryptoRelationshipPublicResponseSerialized): CryptoRelationshipPublicResponse {
        return this.fromAny(value);
    }

    public static fromBase64(value: string): CryptoRelationshipPublicResponse {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }

    /**
     * Creates a relationship response from a CAL handle
     * @param handle The CAL handle to convert from
     * @returns A promise resolving to a relationship response
     */
    public static async fromHandle(
        handle: CryptoRelationshipPublicResponseHandle
    ): Promise<CryptoRelationshipPublicResponse> {
        return CryptoRelationshipPublicResponse.from({
            id: handle.id,
            exchangeKey: handle.exchangeKey,
            signatureKey: handle.signatureKey,
            state: handle.state
        });
    }
}
