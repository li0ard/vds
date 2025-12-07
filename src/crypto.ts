import type { ECDSA } from "@noble/curves/abstract/weierstrass.js";
import { VDSSignature, type Seal } from "./vds.js";
import type { CHash } from "@noble/hashes/utils.js";
import { sha224, sha256, sha384, sha512 } from "@noble/hashes/sha2.js";

/** Seal verifier */
export class SealVerifier {
    /**
     * Seal verifier
     * @param curve Curve from [`@noble/curves`](https://github.com/paulmillr/noble-curves/)
     * @param publicKey Public key bytes (uncompressed format)
     * @param prehash Allow curves with custom hashes (default - `false`)
     */
    constructor(private curve: ECDSA, public publicKey: Uint8Array, private prehash: boolean = false) {}

    /** Curve field size */
    private get fieldSize() {
        return (this.publicKey.length - 1) * 4;
    }

    /** Verify seal */
    verify(seal: Seal): boolean {
        if(!seal.signatureBytes) throw new Error("Empty signature. Can't verify");
        let dataToVerify = seal.signedBytes;

        // `prehash = true` allows curves with custom hashes
        if(!this.prehash) {
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
            prehash: this.prehash
        });
    }
}

/** Seal signer */
export class SealSigner {
    /**
     * Seal signer
     * @param curve Curve from [`@noble/curves`](https://github.com/paulmillr/noble-curves/)
     * @param privateKey Private key bytes
     * @param prehash Allow curves with custom hashes (default - `false`)
     */
    constructor(private curve: ECDSA, private privateKey: Uint8Array, private prehash: boolean = false) {}

    /** Curve field size */
    private get fieldSize() {
        return this.privateKey.length * 8;
    }

    /** Sign seal */
    sign(seal: Seal): VDSSignature {
        let dataToSign = seal.signedBytes;

        // `prehash = true` allows curves with custom hashes
        if(!this.prehash) {
            let digest: CHash;
            if(this.fieldSize <= 224) digest = sha224;
            else if(this.fieldSize >= 225 && this.fieldSize <= 256) digest = sha256;
            else if(this.fieldSize >= 257 && this.fieldSize <= 384) digest = sha384;
            else if(this.fieldSize >= 385 && this.fieldSize <= 512) digest = sha512;
            else throw new Error(`Bit length of Field is out of defined value: ${this.fieldSize}`);

            dataToSign = digest(seal.signedBytes);
        }

        const signature = this.curve.sign(dataToSign, this.privateKey, {
            prehash: this.prehash
        });

        return new VDSSignature(signature.slice(0, signature.length / 2), signature.slice(signature.length / 2));
    }
}