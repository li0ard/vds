import { describe, test, expect } from "bun:test";
import { Seal, Verifier } from "../src";
import { brainpoolP256r1 } from "@noble/curves/misc.js";

const utts5bPublicKey = Buffer.from("0408132A7243B3CCC29C271097081C96A729EEFB8EB93630E536498E9B7CE1CED25D68A789D93BEF39C04715C5AD3915D281C0754ECC08508BF66687EFC630DF88", "hex");
const verifier = new Verifier(brainpoolP256r1, utts5bPublicKey);
describe("Parsing (VDS)", () => {
    test("#1 (v4)", () => {
        const seal = Buffer.from("dc03d9c5d9cac8a73a990f7134b83459fb0602305cba135875976ec066d417b59e8c6abc133c133c133c133c3fef3a2938ee43f1593d1ae52dbb26751fe64b7c133c136b0306d79519a65306ff40a1f621437b25e0dc6177182297c47544890177ebd0e89b1d1ec9f994ed6fe60e5561fac9bc9e723ff8f60c679f6a23b938ee6584f852476f8c72a05e3f9eb87e", "hex");
        const decodedSeal = Seal.decode(seal);

        expect(decodedSeal.header.issuingCountry).toBe("UTO");
        expect(decodedSeal.header.signerIdentifier).toBe("UTTS");
        expect(decodedSeal.header.certificateReference).toBe("5B");
        expect(decodedSeal.header.issuingDate.toISOString()).toBe(new Date(2020, 0, 1).toISOString());
        expect(decodedSeal.header.sigDate.toISOString()).toBe(new Date(2025, 11, 7).toISOString());
        expect(decodedSeal.header.docFeatureRef).toBe(251);
        expect(decodedSeal.header.docTypeCat).toBe(6);
        expect(decodedSeal.header.rawVersion).toBe(3);

        expect(decodedSeal.messageList.some(i => i.tag == 2)).toBeTrue();
        expect(decodedSeal.messageList.some(i => i.tag == 3)).toBeTrue();

        expect(verifier.verifySeal(decodedSeal)).toBeTrue();

        expect(decodedSeal.encoded).toStrictEqual(seal);
    });

    test("#2 (v3)", () => {
        const seal = Buffer.from("dc02d9c5d9cac8a51a780f7134b83459fd020230a56213535bd4caecc87ca4ccaeb4133c133c133c133c133c3fef3a2938ee43f1593d1ae52dbb26751fe64b7c133c136b030859e9203833736d24ff40a353a998b785470536187860093d55325a06e66fe917bfa1f6fb62c5016c66a481ec6f2c7c18da9682f0c2e0b592f6eeb11ca6c6994b37ca2950d6fadd63264d", "hex");
        const decodedSeal = Seal.decode(seal);

        expect(decodedSeal.header.issuingCountry).toBe("UTO");
        expect(decodedSeal.header.signerIdentifier).toBe("UTTS");
        expect(decodedSeal.header.certificateReference).toBe("0005B");
        expect(decodedSeal.header.issuingDate.toISOString()).toBe(new Date(2020, 0, 1).toISOString());
        expect(decodedSeal.header.sigDate.toISOString()).toBe(new Date(2025, 11, 7).toISOString());
        expect(decodedSeal.header.docFeatureRef).toBe(253);
        expect(decodedSeal.header.docTypeCat).toBe(2);
        expect(decodedSeal.header.rawVersion).toBe(2);

        expect(decodedSeal.messageList.some(i => i.tag == 2)).toBeTrue();
        expect(decodedSeal.messageList.some(i => i.tag == 3)).toBeTrue();

        expect(verifier.verifySeal(decodedSeal)).toBeTrue();

        expect(decodedSeal.encoded).toStrictEqual(seal);
    });
});