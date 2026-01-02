import { concatBytes } from "@noble/curves/utils.js";
import { C40Encoder, DateEncoder, DerTLV, parseTLVs } from "../utils.js";
import { deflate, inflate } from "pako";
import { base32nopad } from "@scure/base";
import { AbstractECDSARawSignature, AbstractSeal } from "../generic.js"

/** IDB signature algorithm */
export enum IDBSignatureAlgorithm {
    /** SHA256 with ECDSA */
    SHA256_WITH_ECDSA = 1,
    /** SHA384 with ECDSA */
    SHA384_WITH_ECDSA = 2,
    /** SHA512 with ECDSA */
    SHA512_WITH_ECDSA = 3
}

/**
 * Barcode header
 * 
 * Described by ICAO Datastructure for Barcode section 3.2
 */
export class IDBHeader {
    /**
     * Barcode header
     * @param countryIdentifier Issuing country code
     * @param signatureAlgorithm Signature algorithm (Optional)
     * @param certificateReference Identifier of certificate (Optional)
     * @param signatureCreationDate Signature date (Optional)
     */
    constructor(
        public countryIdentifier: string,
        public signatureAlgorithm: IDBSignatureAlgorithm | null = null,
        public certificateReference: Uint8Array | null = null,
        public signatureCreationDate: string | null = null
    ) {}

    /** Encoded IDB header */
    get encoded(): Uint8Array {
        const buffer: number[] = [];
        buffer.push(...C40Encoder.encode(this.countryIdentifier));
        if(this.signatureAlgorithm) buffer.push(this.signatureAlgorithm);
        if(this.certificateReference) buffer.push(...this.certificateReference);
        if(this.signatureCreationDate) buffer.push(...DateEncoder.encodeMaskedDate(this.signatureCreationDate));

        return new Uint8Array(buffer);
    }

    /** Decode IDB header from bytes */
    static decode(data: Uint8Array): IDBHeader {
        if(!(data.length >= 2 && data.length <= 12)) throw new Error("Header must have length between 2 and 12 bytes");

        let offset = 0;

        const countryIdentifier = C40Encoder.decode(data.subarray(offset, offset + 2)).replaceAll(" ", "<");
        offset += 2;
        if(data.length == 2) return new IDBHeader(countryIdentifier);
        
        const signatureAlgorithm = data[offset];
        offset += 1;

        const certificateReference = data.subarray(offset, offset + 5);
        offset += 5;

        const signatureCreationDate = DateEncoder.decodeMaskedDate(data.subarray(offset, offset + 4));
        offset += 4;

        return new IDBHeader(countryIdentifier, signatureAlgorithm, certificateReference, signatureCreationDate);
    }
}

/**
 * Barcode signature (ECDSA)
 * 
 * Described by ICAO Datastructure for Barcode section 3.5
 */
export class IDBSignature extends AbstractECDSARawSignature {
    static readonly TAG = 0x7F;
    readonly TAG = IDBSignature.TAG;
}

/**
 * Barcode payload
 * 
 * Described by ICAO Datastructure for Barcode section 3
 */
export class IDBPayload {
    /** Message group identifier */
    static readonly MESSAGE_GROUP_TAG = 0x61;
    /** Signer certificate identifier */
    static readonly SIGNER_CERTIFICATE_TAG = 0x7E;
    /**
     * Barcode payload
     * @param header Barcode header
     * @param messageList Barcode messages
     * @param signerCertificate Barcode signer certificate (Optional, last 5 bytes of SHA-1 fingerprint)
     * @param signature Barcode signature (Optional)
     */
    constructor(
        public header: IDBHeader,
        public messageList: DerTLV[],
        public signerCertificate: Uint8Array | null = null,
        public signature: IDBSignature | null = null
    ) {}

    /** Get encoded signer certificate */
    get certificateEncoded(): Uint8Array | null {
        if(this.signerCertificate != null) return new DerTLV(IDBPayload.SIGNER_CERTIFICATE_TAG, this.signerCertificate).encoded;
        return null;
    }
    /** Get encoded messages */
    get messageListEncoded(): Uint8Array {
        return new DerTLV(IDBPayload.MESSAGE_GROUP_TAG, concatBytes(...this.messageList.map(i => i.encoded))).encoded;
    }

    /** Encoded IDB payload */
    get encoded(): Uint8Array {
        let encoded = concatBytes(this.header.encoded, this.messageListEncoded);
        if(this.certificateEncoded != null) encoded = concatBytes(encoded, this.certificateEncoded);
        if(this.signature != null) encoded = concatBytes(encoded, this.signature.encoded);
        else if(this.header.signatureAlgorithm != null) console.warn("Signature algorithm specified, but signature missing");

        return encoded;
    }

    /** Decode IDB payload from bytes */
    static decode(data: Uint8Array, isSigned: boolean): IDBPayload {
        let messageList: DerTLV[] | null = null;
        let signerCertificate: Uint8Array | null = null;
        let signature: IDBSignature | null = null;

        const headerSize = isSigned ? 12 : 2;
        const header = IDBHeader.decode(data.subarray(0, headerSize));
        
        for(const i of parseTLVs(data.subarray(headerSize))) {
            switch(i.tag) {
                case IDBPayload.MESSAGE_GROUP_TAG:
                    messageList = parseTLVs(i.value);
                    break;
                case IDBPayload.SIGNER_CERTIFICATE_TAG:
                    signerCertificate = i.value;
                    break;
                case IDBSignature.TAG:
                    signature = IDBSignature.decode(i.encoded);
                    break;
                default:
                    throw new Error(`Found unknown tag 0x${i.tag.toString(16).padStart(2, "0").toUpperCase()}`);
            }
        }

        if(messageList == null) throw new Error("Missing message group");

        return new IDBPayload(header, messageList, signerCertificate, signature);
    }
}

/**
 * ICAO Datastructure for Barcode (IDB)
 * 
 * Described by ICAO Datastructure for Barcode section 2
 */
export class ICAOBarcode implements AbstractSeal {
    /** Barcode identifier (Old) */
    static readonly BARCODE_IDENTIFIER_OLD = "NDB1";
    /** Barcode identifier */
    static readonly BARCODE_IDENTIFIER = "RDB1";

    private _flag = 0x41;
    /**
     * ICAO Datastructure for Barcode (IDB)
     * @param isSigned Is barcode signed?
     * @param isZipped Is barcode compressed?
     * @param payload Barcode payload
     */
    constructor(isSigned: Boolean, isZipped: Boolean, public payload: IDBPayload) {
        if(isSigned) this._flag += 1;
        if(isZipped) this._flag += 2;
    }

    /** Barcode flag */
    get barcodeFlag(): string { return String.fromCharCode(this._flag); }
    /** Is barcode signed? */
    get isSigned(): boolean { return ((this._flag - 0x41) & 1) == 1; }
    /** Is barcode compressed? */
    get isZipped(): boolean { return ((this._flag - 0x41) & 2) == 2; }

    get signedBytes(): Uint8Array {
        return concatBytes(this.header.encoded, this.payload.messageListEncoded);
    }
    get signatureBytes(): Uint8Array | null {
        return this.payload.signature ? this.payload.signature.toDER() : null;
    }

    /** Barcode header */
    get header(): IDBHeader { return this.payload.header; }
    /** Barcode messages */
    get messageList(): DerTLV[] { return this.payload.messageList; }

    /** Encoded ICAO barcode */
    get encoded(): string {
        const strBuffer: string[] = [ICAOBarcode.BARCODE_IDENTIFIER];
        strBuffer.push(this.barcodeFlag);
        
        const payloadBytes = this.isZipped ? deflate(this.payload.encoded, { level: 9 }) : this.payload.encoded;
        strBuffer.push(base32nopad.encode(payloadBytes));

        return strBuffer.join("");
    }

    /** Decode barcode from string */
    static decode(data: string): ICAOBarcode {
        const barcodeIdentifier = data.substring(0, 4);
        const isIcaoBarcode = barcodeIdentifier == ICAOBarcode.BARCODE_IDENTIFIER || barcodeIdentifier == ICAOBarcode.BARCODE_IDENTIFIER_OLD;
        if (!isIcaoBarcode) throw new Error("Barcode identifier not found");

        const barcodeFlag = data[4];
        const isSigned = ((barcodeFlag.charCodeAt(0) - 0x41) & 1) == 1;
        const isZipped = ((barcodeFlag.charCodeAt(0) - 0x41) & 2) == 2;

        let payloadBytes = base32nopad.decode(data.substring(5));
        if(isZipped) payloadBytes = inflate(payloadBytes);

        return new ICAOBarcode(isSigned, isZipped, IDBPayload.decode(payloadBytes, isSigned));
    }
}