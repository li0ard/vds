import { bytesToNumberBE, concatBytes, numberToBytesBE } from "@noble/curves/utils.js";

/**
 * Date encoder/decoder
 * 
 * Described by ICAO 9303 p.13 section 2.3.1
 */
export class DateEncoder {
    static MASKED_DATE_REGEX = /(.{4})-(.{2})-(.{2})/;

    /** Encode date */
    static encode(date: Date): Uint8Array {
        return numberToBytesBE(parseInt(`${(date.getMonth() + 1).toString().padStart(2, "0")}${(date.getDate()).toString().padStart(2, "0")}${(date.getFullYear()).toString().padStart(4, "0")}`), 3)
    }

    /** Decode date */
    static decode(date: Uint8Array): Date {
        if (date.length !== 3) throw new Error("Expected 3 bytes for date decoding");
        const intValue = bytesToNumberBE(date);

        const day = Number((intValue % 1000000n) / 10000n);
        const month = Number(intValue / 1000000n);
        const year = Number(intValue % 10000n);

        return new Date(year, month - 1, day);
    }

    /** Encode DateTime*/
    static encodeDateTime(date: Date): Uint8Array {
        const formattedDateTime = 
            (date.getMonth() + 1).toString().padStart(2, '0') +
            date.getDate().toString().padStart(2, '0') +
            date.getFullYear().toString().padStart(4, '0') +
            date.getHours().toString().padStart(2, '0') +
            date.getMinutes().toString().padStart(2, '0') +
            date.getSeconds().toString().padStart(2, '0');
        
        return numberToBytesBE(BigInt(formattedDateTime), 6);
    }

    /** Decode DateTime */
    static decodeDateTime(date: Uint8Array): Date {
        if (date.length !== 6) throw new Error("Expected 6 bytes for datetime decoding");

        const paddedDateString = bytesToNumberBE(date).toString().padStart(14, '0');
        const month = parseInt(paddedDateString.substring(0, 2));
        const day = parseInt(paddedDateString.substring(2, 4));
        const year = parseInt(paddedDateString.substring(4, 8));
        const hour = parseInt(paddedDateString.substring(8, 10));
        const minute = parseInt(paddedDateString.substring(10, 12));
        const second = parseInt(paddedDateString.substring(12, 14));
    
        return new Date(year, month - 1, day, hour, minute, second);
    }

    /** Encode masked date */
    static encodeMaskedDate(date: string): Uint8Array {
        if(!date.match(DateEncoder.MASKED_DATE_REGEX)) throw new Error("Date string must be formated as yyyy-MM-dd");

        const formattedDate = date.replace(DateEncoder.MASKED_DATE_REGEX, "$2$3$1").toLowerCase();
        const dateInt = parseInt(formattedDate.replaceAll("x", "0"));
        const dateCharArray = formattedDate.split("");
        let mask = 0;

        for(let i = 0; i < 8; i++)
            if (dateCharArray[i] == 'x') mask |= (0x80 >> i) & 0xFF;

        return new Uint8Array([mask & 0xFF, (dateInt >>> 16) & 0xFF, (dateInt >>> 8) & 0xFF, dateInt & 0xFF]);
    }

    /** Decode masked date */
    static decodeMaskedDate(date: Uint8Array): string {
        if(date.length != 4) throw new Error("Expected 4 bytes for masked date decoding");

        const mask = date[0];
        const intval = bytesToNumberBE(date.subarray(1));
        
        const day = Number((intval % 1000000n) / 10000n);
        const month = Number(intval / 1000000n);
        const year = Number(intval % 10000n);
        const dateCharArray = `${month.toString().padStart(2, '0')}${day.toString().padStart(2, '0')}${year.toString().padStart(4, '0')}`.split("");

        for(let i = 0; i < 8; i++)
            if (((mask >> (7 - i)) & 1) === 1) dateCharArray[i] = 'x';

        return dateCharArray.join("").replace(/(.{2})(.{2})(.{4})/, "$3-$1-$2").toLowerCase();
    }
}

/**
 * String encoder/decoder based on C40 scheme
 * 
 * Described by ICAO 9303 p.13 section 2.6
 */
export class C40Encoder {
    /** Get C40 value from char */
    static getC40Value(c: string): number {
        const value = c.charCodeAt(0) & 0xFF;

        if (value === 32) return 3;
        if (value >= 48 && value <= 57) return value - 44;
        if (value >= 65 && value <= 90) return value - 51;

        throw new Error(`Not a C40 encodable char: ${c} value: ${value}`);
    }

    /** Get char from C40 value */
    static getChar(c40Value: number): string {
        if (c40Value === 3) return " ";
        if (c40Value >= 4 && c40Value <= 13) return String.fromCharCode(c40Value + 44);
        if (c40Value >= 14 && c40Value <= 39) return String.fromCharCode(c40Value + 51);
        if (c40Value === 0) return "";
        
        throw new Error(`Invalid C40 value: ${c40Value}`);
    }

    /** Encode string */
    static encode(string: string): Uint8Array {
        let dataString = string;
        let c1: number, c2: number, c3: number, sum: number;
        let out = [];

        dataString = dataString
            .toUpperCase()
            .replaceAll("<", " ")
            .replaceAll("\r", "")
            .replaceAll("\n", "");
        
        let len = dataString.length;

        for(let i = 0; i < len; i++) {
            if (i % 3 == 0) {
                if (i + 2 < len) {
                    c1 = C40Encoder.getC40Value(dataString[i]);
                    c2 = C40Encoder.getC40Value(dataString[i + 1]);
                    c3 = C40Encoder.getC40Value(dataString[i + 2]);
                    sum = (1600 * c1) + (40 * c2) + c3 + 1;

                    out.push(Math.floor(sum / 256));
                    out.push(sum % 256);
                } else if (i + 1 < len) {
                    c1 = C40Encoder.getC40Value(dataString[i])
                    c2 = C40Encoder.getC40Value(dataString[i + 1])
                    sum = (1600 * c1) + (40 * c2) + 1

                    out.push(Math.floor(sum / 256));
                    out.push(sum % 256);
                }  else {
                    out.push(254);
                    out.push((dataString[i].charCodeAt(0) & 0xFF) + 1);  
                }
            }
        }

        return new Uint8Array(out);
    }

    /** Decode string */
    static decode(bytes: Uint8Array): string {
        const result: string[] = [];
        
        for (let idx = 0; idx < bytes.length - 1; idx += 2) {
            const i1 = bytes[idx];
            const i2 = bytes[idx + 1];
            
            if (i1 === 0xFE) result.push(String.fromCharCode(i2 - 1));
            else {
                const v16 = ((i1 & 0xFF) << 8) + (i2 & 0xFF) - 1;
                
                let temp = Math.floor(v16 / 1600);
                const u1 = temp;
                let remainder = v16 - temp * 1600;
                
                temp = Math.floor(remainder / 40);
                const u2 = temp;
                const u3 = remainder - temp * 40;
                
                if (u1 !== 0) result.push(C40Encoder.getChar(u1));
                if (u2 !== 0) result.push(C40Encoder.getChar(u2));
                if (u3 !== 0) result.push(C40Encoder.getChar(u3));
            }
        }
        
        return result.join("");
    }
}

/** DER-TLV encoder/decoder */
export class DerTLV {
    /**
     * DER-TLV encoder/decoder
     * @param tag Tag
     * @param value Value
     */
    constructor(public tag: number, public value: Uint8Array) {}

    /** Encodes length according to ASN.1 rules */
    static getDerLength(length: number): Uint8Array {
        if(length <= 127) return new Uint8Array([length & 0xff]);
        else {
            const lengthBytes = numberToBytesBE(length, 4);
            let byteCount = 1;
            while (byteCount < 4 && lengthBytes[byteCount] === 0) byteCount++;
            const actualLengthBytes = lengthBytes.slice(4 - byteCount);
            const firstByte = (0x80 | actualLengthBytes.length) & 0xFF;
            
            return concatBytes(new Uint8Array([firstByte]), actualLengthBytes);
        }
    }

    /** Encode value as DER coded INTEGER */
    static getDerInteger(value: Uint8Array): Uint8Array {
        let positiveValue: Uint8Array;
        if (value[0] & 0x80) {
            const temp = new Uint8Array(value.length + 1);
            temp[0] = 0;
            temp.set(value, 1);
            positiveValue = temp;
        } else {
            let startIndex = 0;
            while (startIndex < value.length - 1 && value[startIndex] === 0) startIndex++;
            positiveValue = value.slice(startIndex);
        }

        return new DerTLV(2, positiveValue).encoded;
    }

    /** Encode to DER-TLV */
    get encoded(): Uint8Array {
        const length = DerTLV.getDerLength(this.value.length);
        return concatBytes(new Uint8Array([this.tag]), length, this.value)
    }

    /** Decode from DER-TLV */
    static decode(derBytes: Uint8Array): DerTLV | null {
        if (derBytes.length == 0) return null

        let tag = derBytes[0];
        let lengthByteCount = 1;
        let length = derBytes[1] & 0xff;
    
        if (length > 127) {
            let lengthOfLength = length - 128;
            lengthByteCount += lengthOfLength;
            length = 0;

            for (let i = 2; i < 2 + lengthOfLength; i++) length = (length << 8) | (derBytes[i] & 0xFF);
        }

        return new DerTLV(tag, derBytes.slice(1 + lengthByteCount, 1 + lengthByteCount + length))
    }
}

export const parseTLVs = (rawBytes: Uint8Array): DerTLV[] => {
    const derTlvList: DerTLV[] = [];
    let position = 0;

    while (position < rawBytes.length) {
        if (position >= rawBytes.length) throw new Error("Unexpected end of data while reading tag");

        const tag = rawBytes[position++];
        if (position >= rawBytes.length) throw new Error("Unexpected end of data while reading length");
        let le = rawBytes[position++] & 0xff;

        if (le === 0x81) {
            le = rawBytes[position++] & 0xff;
        } else if (le === 0x82) {
            le = ((rawBytes[position++] & 0xff) << 8) | (rawBytes[position++] & 0xff);
        } else if (le === 0x83) {
            le = ((rawBytes[position++] & 0xff) << 16) | ((rawBytes[position++] & 0xff) << 8) | (rawBytes[position++] & 0xff);
        } else if (le > 0x7F) {
            const hexValue = le.toString(16).padStart(2, '0').toUpperCase();
            throw new Error(`Can't decode length: ${hexValue}`);
        }

        const value = rawBytes.slice(position, position + le);
        position += le;
            
        derTlvList.push(new DerTLV(tag, value));
    }

    return derTlvList;
}

export const intToBytesBE = (value: bigint | number): Uint8Array => {
    if(typeof value == "number") value = BigInt(value);
    if(value < 0n) throw new Error("Feature MUST be positive integer");
    if (value === 0n) return new Uint8Array([0]);

    const bytes: number[] = [];
    let v = value;

    while (v > 0) {
        bytes.unshift(Number(v & 0xffn));
        v >>= 8n;
    }

    return new Uint8Array(bytes);
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
            parsed.value.slice(0, parsed.value.length / 2),
            parsed.value.slice(parsed.value.length / 2, parsed.value.length)
        );
    }
}