import { bytesToNumberBE } from "@noble/curves/utils.js";
import { concatBytes } from "@noble/hashes/utils.js";
import { DerTLV } from "./utils.js";

/** Abstract seal */
export abstract class AbstractSeal {
    /** Signed bytes */
    abstract get signedBytes(): Uint8Array;

    /** Signature bytes */
    abstract get signatureBytes(): Uint8Array | null;

    /** Encoded seal/barcode */
    abstract get encoded(): unknown;
}

/** Abstract ECDSA signature (Raw format) */
export abstract class AbstractECDSARawSignature {
    static readonly TAG: number;
    abstract readonly TAG: number;
    private _r: Uint8Array;
    private _s: Uint8Array;

    constructor(r: Uint8Array, s: Uint8Array) {
        this._r = r;
        this._s = s;
    }

    /** `r` as bigint */
    get r(): bigint { return bytesToNumberBE(this._r); }
    /** `r` as bytes */
    get rBytes(): Uint8Array { return this._r; }
    /** `s` as bigint */
    get s(): bigint { return bytesToNumberBE(this._s); }
    /** `s` as bytes */
    get sBytes(): Uint8Array { return this._s; }

    /** Encoded IDB signature */
    get encoded(): Uint8Array {
        return new DerTLV(this.TAG, concatBytes(this.rBytes, this.sBytes)).encoded;
    }

    /** Encoded IDB signature (as ASN.1) */
    toDER(): Uint8Array {
        return new DerTLV(0x30, concatBytes(
            DerTLV.getDerInteger(this.rBytes),
            DerTLV.getDerInteger(this.sBytes),
        )).encoded;
    }

    static decode<T extends AbstractECDSARawSignature>(
        this: {
            new (r: Uint8Array, s: Uint8Array): T;
            readonly TAG: number;
        },
        data: Uint8Array
    ): T {
        if(data[0] != this.TAG) throw new Error("Signature tag mismatch");
        const parsed = DerTLV.decode(data);
        if(parsed == null) throw new Error("Invalid signature");
        return new this(
            parsed.value.subarray(0, parsed.value.length / 2),
            parsed.value.subarray(parsed.value.length / 2, parsed.value.length)
        );
    }
}