import type { ECDSA } from "@noble/curves/abstract/weierstrass.js";
import { VDSSignature, type Seal } from "./vds/vds.js";
import { IDBSignatureAlgorithm, IDBSignature, type ICAOBarcode } from "./idb/idb.js";
import type { CHash } from "@noble/hashes/utils.js";
import { sha224, sha256, sha384, sha512 } from "@noble/hashes/sha2.js";

/** Seal/barcode verifier */
export class Verifier {
    /**
     * Seal/barcode verifier
     * @param curve Curve from [`@noble/curves`](https://github.com/paulmillr/noble-curves/)
     * @param publicKey Public key bytes (uncompressed format)
     */
    constructor(private curve: ECDSA, public publicKey: Uint8Array) {}

    /** Curve field size */
    private get fieldSize(): number { return (this.publicKey.length - 1) * 4; }

    /**
     * Verify seal (VDS)
     * @param seal Seal object
     * @param prehash Allow curves with custom hashes (default - `false`)
     */
    verifySeal(seal: Seal, prehash: boolean = false): boolean {
        if(!seal.signatureBytes) throw new Error("Empty signature. Can't verify");
        let dataToVerify = seal.signedBytes;

        // `prehash = true` allows curves with custom hashes
        if(!prehash) {
            let digest: CHash;
            if(this.fieldSize <= 224) digest = sha224;
            else if(this.fieldSize >= 225 && this.fieldSize <= 256) digest = sha256;
            else if(this.fieldSize >= 257 && this.fieldSize <= 384) digest = sha384;
            else if(this.fieldSize >= 385 && this.fieldSize <= 512) digest = sha512;
            else throw new Error(`Bit length of Field is out of defined value: ${this.fieldSize}`);

            dataToVerify = digest(seal.signedBytes);
        }
        
        return this.curve.verify(seal.signatureBytes, dataToVerify, this.publicKey, {
            format: "der",
            lowS: false,
            prehash: prehash
        });
    }

    /**
     * Verify barcode (IDB)
     * @param barcode Barcode object
     */
    verifyBarcode(barcode: ICAOBarcode): boolean {
        if(!barcode.signatureBytes) throw new Error("Empty signature. Can't verify");
        if(!barcode.payload.header.signatureAlgorithm) throw new Error("Empty signature algorithm. Can't verify");

        let digest: CHash;
        switch(barcode.payload.header.signatureAlgorithm) {
            case IDBSignatureAlgorithm.SHA256_WITH_ECDSA:
                digest = sha256;
                break;
            case IDBSignatureAlgorithm.SHA384_WITH_ECDSA:
                digest = sha384;
                break;
            case IDBSignatureAlgorithm.SHA512_WITH_ECDSA:
                digest = sha512;
                break;
            default:
                throw new Error("Invalid signature algorithm");
        }

        return this.curve.verify(barcode.signatureBytes, digest(barcode.signedBytes), this.publicKey, {
            format: "der",
            lowS: false,
            prehash: false
        });
    }
}

/** Seal/barcode signer */
export class Signer {
    /**
     * Seal/barcode signer
     * @param curve Curve from [`@noble/curves`](https://github.com/paulmillr/noble-curves/)
     * @param privateKey Private key bytes
     */
    constructor(private curve: ECDSA, private privateKey: Uint8Array) {}

    /** Curve field size */
    private get fieldSize(): number { return this.privateKey.length * 8; }

    /**
     * Sign seal (VDS)
     * @param seal Seal object
     * @param prehash Allow curves with custom hashes (default - `false`)
     */
    signSeal(seal: Seal, prehash: boolean = false): VDSSignature {
        let dataToSign = seal.signedBytes;

        // `prehash = true` allows curves with custom hashes
        if(!prehash) {
            let digest: CHash;
            if(this.fieldSize <= 224) digest = sha224;
            else if(this.fieldSize >= 225 && this.fieldSize <= 256) digest = sha256;
            else if(this.fieldSize >= 257 && this.fieldSize <= 384) digest = sha384;
            else if(this.fieldSize >= 385 && this.fieldSize <= 512) digest = sha512;
            else throw new Error(`Bit length of Field is out of defined value: ${this.fieldSize}`);

            dataToSign = digest(seal.signedBytes);
        }

        const signature = this.curve.sign(dataToSign, this.privateKey, { prehash: prehash });

        return new VDSSignature(signature.subarray(0, signature.length / 2), signature.subarray(signature.length / 2));
    }

    /**
     * Sign barcode (IDB)
     * @param barcode Barcode object
     */
    signBarcode(barcode: ICAOBarcode): IDBSignature {
        if(!barcode.payload.header.signatureAlgorithm) throw new Error("Empty signature algorithm. Can't sign");

        let digest: CHash;
        switch(barcode.payload.header.signatureAlgorithm) {
            case IDBSignatureAlgorithm.SHA256_WITH_ECDSA:
                digest = sha256;
                break;
            case IDBSignatureAlgorithm.SHA384_WITH_ECDSA:
                digest = sha384;
                break;
            case IDBSignatureAlgorithm.SHA512_WITH_ECDSA:
                digest = sha512;
                break;
            default:
                throw new Error("Invalid signature algorithm");
        }

        const signature = this.curve.sign(digest(barcode.signedBytes), this.privateKey, { prehash: false });

        return new IDBSignature(signature.subarray(0, signature.length / 2), signature.subarray(signature.length / 2));
    }
}