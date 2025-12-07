import { bytesToNumberBE, concatBytes } from "@noble/curves/utils.js";
import { C40Encoder, DateEncoder, DerTLV, parseTLVs } from "./utils.js";

/**
 * Seal header
 * 
 * Described by ICAO 9303 p.13 section 2.2
 */
export class VDSHeader {
    /** Offset for decoding */
    public _offset = 0;

    /**
     * Seal header
     * @param issuingCountry Issuing country code
     * @param signerIdentifier Identifier of signer
     * @param certificateReference Identifier of certificate
     * @param issuingDate Issuing date
     * @param sigDate Signature date
     * @param docFeatureRef Document feature identifier
     * @param docTypeCat Document type
     * @param rawVersion Version of encoding (default - ICAO version 4 (`0x03`))
     */
    constructor(
        public issuingCountry: string = "UTO",
        public signerIdentifier: string = "UTXX",
        public certificateReference: string = "12345",
        public issuingDate: Date = new Date(),
        public sigDate: Date = new Date(),
        public docFeatureRef: number = 0,
        public docTypeCat: number = 0,
        public rawVersion: number = 3
    ) {}

    /** Identifier of signer certificate */
    get signerCertRef(): string {
        let certRefInteger = "0";
        if (this.certificateReference) {
            const trimmed = this.certificateReference.replace(/^0+/, '');
            certRefInteger = trimmed === '' ? '0' : trimmed;
        }
        
        return (this.signerIdentifier + certRefInteger).toUpperCase();
    }

    /** Identifier of document */
    get documentRef(): number {
        return ((this.docFeatureRef & 0xFF) << 8) + (this.docTypeCat & 0xFF)
    }

    private get encodedSignerIdentifierAndCertificateReference(): string {
        if(this.rawVersion == 2) {
            return `${this.signerIdentifier || ''}${(this.certificateReference || '').padStart(5, ' ')}`.toUpperCase().replace(/ /g, '0');
        }
        else if(this.rawVersion == 3) {
            const certRef = this.certificateReference || '';
            const certRefLengthHex = certRef.length.toString(16).padStart(2, '0');
            return `${this.signerIdentifier || ''}${certRefLengthHex}${certRef}`.toUpperCase();
        }
        else return "";
    }
    
    /** Encoded VDS header */
    get encoded(): Uint8Array {
        const buffer: number[] = [0xDC];
        buffer.push(this.rawVersion);
        buffer.push(...C40Encoder.encode(this.issuingCountry));
        buffer.push(...C40Encoder.encode(this.encodedSignerIdentifierAndCertificateReference));
        buffer.push(...DateEncoder.encode(this.issuingDate));
        buffer.push(...DateEncoder.encode(this.sigDate));
        buffer.push(this.docFeatureRef);
        buffer.push(this.docTypeCat);

        return new Uint8Array(buffer);
    }

    /** Decode VDS header from bytes */
    static decode(data: Uint8Array): VDSHeader {
        let offset = 0;

        const magicByte = data[offset];
        offset += 1;

        if(magicByte != 0xDC) throw new Error("Magic Constant mismatch");

        const rawVersion = data[offset];
        offset += 1;

        if(!(rawVersion == 2 || rawVersion == 3)) throw new Error("Unsupported raw version");

        const issuingCountry = C40Encoder.decode(data.slice(offset, offset + 2))
        offset += 2;

        let signerIdentifier: string, certificateReference: string;
        if(rawVersion == 3) { // ICAO version 4
            let signerIdentifierAndCertRefLength = C40Encoder.decode(data.slice(offset, offset + 4));
            offset += 4;
            signerIdentifier = signerIdentifierAndCertRefLength.substring(0, 4);
            
            let certRefLength = parseInt(signerIdentifierAndCertRefLength.substring(4), 16);
            let bytesToDecode = (Math.floor((certRefLength - 1) / 3) * 2) + 2;
            
            certificateReference = C40Encoder.decode(data.slice(offset, offset + bytesToDecode));
            offset += bytesToDecode;
        } else { // ICAO version 3
            let signerCertRef = C40Encoder.decode(data.slice(offset, offset + 6));
            offset += 6;
            signerIdentifier = signerCertRef.substring(0, 4);
            certificateReference = signerCertRef.substring(4)
        }
        
        const issuingDate = DateEncoder.decode(data.slice(offset, offset + 3));
        offset += 3;
        
        const sigDate = DateEncoder.decode(data.slice(offset, offset + 3));
        offset += 3;

        const docFeatureRef = data[offset];
        offset += 1;
        const docTypeCat = data[offset];
        offset += 1;
        
        const decoded = new VDSHeader(issuingCountry, signerIdentifier, certificateReference, issuingDate, sigDate, docFeatureRef, docTypeCat, rawVersion);
        decoded._offset = offset;
        return decoded
    }
}

/**
 * Seal signature (ECDSA)
 * 
 * Described by ICAO 9303 p.13 section 2.4
 */
export class VDSSignature {
    static readonly TAG = 0xff;
    private _r: Uint8Array;
    private _s: Uint8Array;

    /**
     * Seal signature (ECDSA)
     * @param r ECDSA `r` value
     * @param s ECDSA `s` value
     */
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

    /** Encoded VDS signature */
    get encoded(): Uint8Array {
        return new DerTLV(VDSSignature.TAG, concatBytes(this.rBytes, this.sBytes)).encoded;
    }

    /** Encoded VDS signature (as ASN.1) */
    toDER(): Uint8Array {
        return new DerTLV(0x30, concatBytes(
            DerTLV.getDerInteger(this.rBytes),
            DerTLV.getDerInteger(this.sBytes),
        )).encoded;
    }

    /** Decode VDS signature from bytes */
    static decode(data: Uint8Array): VDSSignature {
        if(data[0] != VDSSignature.TAG) throw new Error("Signature tag mismatch");

        const parsed = DerTLV.decode(data);
        if(parsed == null) throw new Error("Invalid signature");
        return new VDSSignature(
            parsed.value.slice(0, parsed.value.length / 2),
            parsed.value.slice(parsed.value.length / 2, parsed.value.length)
        );
    }
}

/**
 * Visible digital seal (VDS)
 * 
 * Described by ICAO p.13 section 2
 */
export class Seal {
    /**
     * Visible digital seal (VDS)
     * @param header VDS header
     * @param messageList VDS messages
     * @param signature VDS signature
     */
    constructor(
        public header: VDSHeader,
        public messageList: DerTLV[],
        public signature: VDSSignature | null = null
    ) {}

    /** Encoded visible digital seal */
    get encoded(): Uint8Array {
        let encoded = this.signedBytes;
        if(this.signature) encoded = concatBytes(encoded, this.signature.encoded);
        
        return encoded;
    }

    /** Signed bytes */
    get signedBytes(): Uint8Array {
        return concatBytes(this.header.encoded, ...this.messageList.map(i => i.encoded));
    }
    /** Signature bytes */
    get signatureBytes(): Uint8Array | null {
        return this.signature ? this.signature.toDER() : null;
    }

    /** Decode visible digital seal from bytes */
    static decode(data: Uint8Array): Seal {
        const header = VDSHeader.decode(data);
        let offset = header._offset;
        const messageList: DerTLV[] = [];
        let signature = null;

        for(const i of parseTLVs(data.subarray(offset))) {
            if(i.tag === 0xff) signature = VDSSignature.decode(i.encoded);
            else messageList.push(i);
        }
        
        return new Seal(header, messageList, signature);
    }
}
