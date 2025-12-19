import { concatBytes } from "@noble/curves/utils.js";
import { AbstractECDSARawSignature, C40Encoder, DateEncoder, DerTLV, parseTLVs } from "../utils.js";

/**
 * Seal header
 * 
 * Described by ICAO 9303 p.13 section 2.2
 */
export class VDSHeader {
    static readonly TAG = 0xDC;

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
    ) {
        if(!(docFeatureRef >= 1 && docFeatureRef <= 254)) throw new Error("docFeatureRef MUST be in range between 1 and 254");
        // Standard says: "Odd numbers in the range between 01dec and 253dec SHALL be used for ICAO-specified Document Type Categories"
        // but all samples using even number, so we check only range
        if(!(docTypeCat >= 1 && docTypeCat <= 253)) throw new Error("docTypeCat MUST be in range between 1 and 253");
    }

    /** Identifier of signer certificate */
    get signerCertRef(): string {
        let certRefInteger = "0";
        if (this.certificateReference) {
            const trimmed = this.certificateReference.replace(/^0+/, '');
            certRefInteger = trimmed === '' ? '0' : trimmed;
        }
        
        return (this.signerIdentifier + certRefInteger).toUpperCase();
    }

    /** Identifier of document (`docFeatureRef || docTypeCat`) */
    get documentRef(): number {
        return ((this.docFeatureRef & 0xFF) << 8) + (this.docTypeCat & 0xFF);
    }
    set documentRef(documentRef: number) {
        this.docFeatureRef = (documentRef >> 8) & 0xFF;
        this.docTypeCat = documentRef & 0xFF;
    }

    /** Version of VDS (`rawVersion` + 1) */
    get version(): number { return this.rawVersion + 1; }

    private get encodedSignerIdentifierAndCertificateReference(): string {
        if(this.rawVersion == 2) {
            if(this.certificateReference.length > 5) throw new Error("For version 3 certificateReference MUST be exactly five characters");
            return `${this.signerIdentifier || ''}${(this.certificateReference || '').padStart(5, ' ')}`.toUpperCase().replace(/ /g, '0');
        }
        else if(this.rawVersion == 3) {
            const certRef = this.certificateReference || '';
            return `${this.signerIdentifier || ''}${certRef.length.toString(16).padStart(2, '0')}${certRef}`.toUpperCase();
        }
        else return "";
    }
    
    /** Encoded VDS header */
    get encoded(): Uint8Array {
        const buffer: number[] = [VDSHeader.TAG];
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
        if(magicByte != VDSHeader.TAG) throw new Error("Magic Constant mismatch");

        const rawVersion = data[offset];
        offset += 1;
        if(!(rawVersion == 2 || rawVersion == 3)) throw new Error("Unsupported raw version");

        const issuingCountry = C40Encoder.decode(data.slice(offset, offset + 2));
        offset += 2;

        let signerIdentifier: string, certificateReference: string;
        if(rawVersion == 3) { // ICAO version 4
            const signerIdentifierAndCertRefLength = C40Encoder.decode(data.slice(offset, offset + 4));
            offset += 4;
            signerIdentifier = signerIdentifierAndCertRefLength.substring(0, 4);
            
            const certRefLength = parseInt(signerIdentifierAndCertRefLength.substring(4), 16);
            const bytesToDecode = (Math.floor((certRefLength - 1) / 3) * 2) + 2;
            
            certificateReference = C40Encoder.decode(data.slice(offset, offset + bytesToDecode));
            offset += bytesToDecode;
        } else { // ICAO version 3
            const signerCertRef = C40Encoder.decode(data.slice(offset, offset + 6));
            offset += 6;
            signerIdentifier = signerCertRef.substring(0, 4);
            certificateReference = signerCertRef.substring(4);
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
        return decoded;
    }
}

/**
 * Seal signature (ECDSA)
 * 
 * Described by ICAO 9303 p.13 section 2.4
 */
export class VDSSignature extends AbstractECDSARawSignature {
    static readonly TAG = 0xFF;
    readonly TAG = VDSSignature.TAG;
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

    /** Signed bytes */
    get signedBytes(): Uint8Array {
        return concatBytes(this.header.encoded, ...this.messageList.map(i => i.encoded));
    }
    /** Signature bytes */
    get signatureBytes(): Uint8Array | null {
        return this.signature ? this.signature.toDER() : null;
    }

    /** Encoded visible digital seal */
    get encoded(): Uint8Array {
        let encoded = this.signedBytes;
        if(this.signature) encoded = concatBytes(encoded, this.signature.encoded);
        
        return encoded;
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
