import { describe, test, expect } from "bun:test";
import { DerTLV, FeatureCoding, decodeSeal, encodeSeal, Seal, VDSDocument, VDSProp } from "../src";
import { equalBytes } from "@noble/curves/utils.js";

const compareMessageLists = (a: DerTLV[], b: DerTLV[]): boolean => {
    if (a.length !== b.length) return false;

    const map1 = new Map<number, Uint8Array>(a.map(i => [i.tag, i.value]));
    const map2 = new Map<number, Uint8Array>(b.map(i => [i.tag, i.value]));
    for (const [tag, value1] of map1) {
        const value2 = map2.get(tag);
        if (!value2 || !equalBytes(value1, value2)) return false;
    }

    return true;
}

@VDSDocument({ documentRef: 0xfd02, version: 3 })
class ArrivalAttestation {
    @VDSProp({ tag: 2, coding: FeatureCoding.MRZ })
    mrz!: string;

    @VDSProp({ tag: 3, coding: FeatureCoding.C40_STRING })
    azr!: string;
}

@VDSDocument({ documentRef: 0xf908, version: 4 })
class AddressStickerID {
    @VDSProp({ tag: 1, coding: FeatureCoding.C40_STRING })
    documentNumber!: string;

    @VDSProp({ tag: 2, coding: FeatureCoding.C40_STRING })
    ags!: string;

    @VDSProp({ tag: 3, coding: FeatureCoding.C40_STRING })
    address!: string;
}

@VDSDocument({ documentRef: 0xf80a, version: 4 })
class AddressStickerPassport {
    @VDSProp({ tag: 1, coding: FeatureCoding.C40_STRING })
    documentNumber!: string;

    @VDSProp({ tag: 2, coding: FeatureCoding.C40_STRING })
    ags!: string;

    @VDSProp({ tag: 3, coding: FeatureCoding.C40_STRING })
    postalCode!: string;
}

@VDSDocument({ documentRef: 0x5e03, version: 4 })
class ICAOEmergencyTravelDocument {
    @VDSProp({ tag: 2, coding: FeatureCoding.MRZ })
    mrz!: string;
}

@VDSDocument({ documentRef: 0x5d01, version: 4 })
class ICAOVisa {
    @VDSProp({ tag: 1, coding: FeatureCoding.MRZ, optional: true })
    mrz_mrva?: string;

    @VDSProp({ tag: 2, coding: FeatureCoding.MRZ, optional: true })
    mrz_mrvb?: string;

    @VDSProp({ tag: 3, coding: FeatureCoding.INT })
    entries!: bigint;

    @VDSProp({ tag: 4, coding: FeatureCoding.BINARY })
    duration!: Uint8Array;

    @VDSProp({ tag: 5, coding: FeatureCoding.C40_STRING })
    passportNumber!: string;

    @VDSProp({ tag: 6, coding: FeatureCoding.BINARY, optional: true })
    type?: Uint8Array;

    @VDSProp({ tag: 7, coding: FeatureCoding.BINARY, optional: true })
    features?: Uint8Array;
}

@VDSDocument({ documentRef: 0xfb06, version: 4 })
class ResidencePermit {
    @VDSProp({ tag: 2, coding: FeatureCoding.MRZ })
    mrz!: string;

    @VDSProp({ tag: 3, coding: FeatureCoding.C40_STRING })
    passportNumber!: string;
}

@VDSDocument({ documentRef: 0xfc04, version: 3 })
class SocialInsuranceCard {
    @VDSProp({ tag: 1, coding: FeatureCoding.C40_STRING })
    insuranceNumber!: string;

    @VDSProp({ tag: 2, coding: FeatureCoding.UTF8_STRING })
    surname!: string;

    @VDSProp({ tag: 3, coding: FeatureCoding.UTF8_STRING })
    firstName!: string;

    @VDSProp({ tag: 4, coding: FeatureCoding.UTF8_STRING })
    birthName!: string;
}

@VDSDocument({ documentRef: 0xfa06, version: 4 })
class SupplementarySheet {
    @VDSProp({ tag: 4, coding: FeatureCoding.MRZ })
    mrz!: string;

    @VDSProp({ tag: 5, coding: FeatureCoding.C40_STRING })
    number!: string;
}

describe("Feature", () => {
    test("#1 (ICAO_VISA)", () => {
        const seal = Buffer.from("dc03d9c5d9cac8a73a990f7134b834595d01022cdd52134a74da1347c6fed95cb89f9fce133c133c133c133c203833734aaf47f0c32f1a1e20eb2625393afe310403a00000050633be1fed20c603010c0601aa0701bbff400b276b4522526b723e2140f14bef1c25048cfed9223268c24337e7a6b5b9f02b1e15c86734ef7101d983869278ce1066694dd80e8b842b82b592db6fd56c10ae", "hex");
        const decodedSeal = Seal.decode(seal);
        const mapped = decodeSeal(decodedSeal, ICAOVisa)

        expect(mapped.mrz_mrvb).toBe("VCD<<DENT<<ARTHUR<PHILIP<<<<<<<<<<<<1234567XY7GBR5203116M2005250");
        expect(mapped.entries).toBe(12n);
        expect(mapped.duration).toStrictEqual(new Uint8Array([0xA0,0,0]));
        expect(mapped.passportNumber).toBe("47110815P");
        expect(mapped.type).toStrictEqual(new Uint8Array([0xAA]));
        expect(mapped.features).toStrictEqual(new Uint8Array([0xBB]));
        expect(compareMessageLists(encodeSeal(mapped), decodedSeal.messageList)).toBeTrue();
    });

    test("#2 (ARRIVAL_ATTESTATION)", () => {
        const seal = Buffer.from("dc02d9c5d9cac8a51a780f7134b83459fd020230a56213535bd4caecc87ca4ccaeb4133c133c133c133c133c3fef3a2938ee43f1593d1ae52dbb26751fe64b7c133c136b030859e9203833736d24ff40a353a998b785470536187860093d55325a06e66fe917bfa1f6fb62c5016c66a481ec6f2c7c18da9682f0c2e0b592f6eeb11ca6c6994b37ca2950d6fadd63264d", "hex");
        const decodedSeal = Seal.decode(seal);
        const mapped = decodeSeal(decodedSeal, ArrivalAttestation);

        expect(mapped.mrz).toBe("MED<<MANNSENS<<MANNY<<<<<<<<<<<<<<<<6525845096USA7008038M2201018<<<<<<06");
        expect(mapped.azr).toBe("ABC123456DEF");
        expect(compareMessageLists(encodeSeal(mapped), decodedSeal.messageList)).toBeTrue();
    });

    test("#3 (ADDRESS_STICKER_ID)", () => {
        const seal = Buffer.from("dc03d9c5d9cac8a73a990f7134b83459f9080106cf3519af974c02061a70208519a1030e395e463e740c749fad19d31efe32ff40a31bf6877ef4b1a9c49b80aa52dddad07e70f55fd5f0cead9d46aaf2abde5a5661ae81ae9fea2b99a1066294d7b758074b286e0c99b198a6b48f299d07d55443", "hex");
        const decodedSeal = Seal.decode(seal);
        const mapped = decodeSeal(decodedSeal, AddressStickerID);

        expect(mapped.documentNumber).toBe("T2000AK47");
        expect(mapped.ags).toBe("05314000");
        expect(mapped.address).toBe("53175HEINEMANNSTR11");
        expect(compareMessageLists(encodeSeal(mapped), decodedSeal.messageList)).toBeTrue();
    });

    test("#4 (ADDRESS_STICKER_PASSPORT)", () => {
        const seal = Buffer.from("dc03d9c5d9cac8a73a990f7134b83459f80a0106b77a38e596ce02061a203a4d1fe1030426532081ff409238e9e0323ba470be32f6d2ece1d12ee34ccc69f13efeb206d729369ae70b2a2965694e5c88c46e2bf9e8b6b28197c4e1f807af826295f1e571159e64b8bf2b", "hex");
        const decodedSeal = Seal.decode(seal);
        const mapped = decodeSeal(decodedSeal, AddressStickerPassport);

        expect(mapped.documentNumber).toBe("PA5500K11");
        expect(mapped.ags).toBe("03359010");
        expect(mapped.postalCode).toBe("21614");
        expect(compareMessageLists(encodeSeal(mapped), decodedSeal.messageList)).toBeTrue();
    });

    test("#5 (RESIDENCE_PERMIT)", () => {
        const seal = Buffer.from("dc03d9c5d9cac8a73a990f7134b83459fb0602305cba135875976ec066d417b59e8c6abc133c133c133c133c3fef3a2938ee43f1593d1ae52dbb26751fe64b7c133c136b0306d79519a65306ff40a1f621437b25e0dc6177182297c47544890177ebd0e89b1d1ec9f994ed6fe60e5561fac9bc9e723ff8f60c679f6a23b938ee6584f852476f8c72a05e3f9eb87e", "hex");
        const decodedSeal = Seal.decode(seal);
        const mapped = decodeSeal(decodedSeal, ResidencePermit);

        expect(mapped.mrz).toBe("ATD<<RESIDORCE<<ROLAND<<<<<<<<<<<<<<6525845096USA7008038M2201018<<<<<<06");
        expect(mapped.passportNumber).toBe("UFO001979");
        expect(compareMessageLists(encodeSeal(mapped), decodedSeal.messageList)).toBeTrue();
    });

    test("#6 (SOCIAL_INSURANCE_CARD)", () => {
        const seal = Buffer.from("dc02d9c5d9cac8a51a780f7134b83459fc0401083fee456d2de019a8020b506572736368776569c39f03054f7363617204134ac3a2636f62c3a96e69646963747572697573ff40350f4b68832a812cb9afdd2eec0b1c6c8a5fabba3f48d4a550af0305a2d23807a9c16d0e49b65a61e294521a30b0b14a68d13b8b981667d200e9036da4e93f75", "hex");
        const decodedSeal = Seal.decode(seal);
        const mapped = decodeSeal(decodedSeal, SocialInsuranceCard);

        expect(mapped.insuranceNumber).toBe("65170839J003");
        expect(mapped.surname).toBe("Perschweiß");
        expect(mapped.firstName).toBe("Oscar");
        expect(mapped.birthName).toBe("Jâcobénidicturius");
        expect(compareMessageLists(encodeSeal(mapped), decodedSeal.messageList)).toBeTrue();
    });

    test("#7 (ICAO_EMERGENCY_TRAVEL_DOCUMENT)", () => {
        const seal = Buffer.from("dc03d9c5d9cac8a73a990f7134b834595e0302308a0d62b9d917a4cca93ca4d0edfc133c133c133c133c133c3fef3a2938ee43f1593d1ae52dbb26751fe64b7c133c136bff403644690e5f2dd4e39b8bf10b4db669a38e60c8e6a46b3da0d7ad0f6aaf59af2326e924e4f96033ea096e89b8a5265aa9f2a39435f17120febf9334af51618d94", "hex");
        const decodedSeal = Seal.decode(seal);
        const mapped = decodeSeal(decodedSeal, ICAOEmergencyTravelDocument);

        expect(mapped.mrz).toBe("I<GBRSUPAMANN<<MARY<<<<<<<<<<<<<<<<<6525845096USA7008038M2201018<<<<<<06");
        expect(compareMessageLists(encodeSeal(mapped), decodedSeal.messageList)).toBeTrue();
    });

    test("#8 (SUPPLEMENTARY_SHEET)", () => {
        const seal = Buffer.from("dc03d9c5d9cac8a73a990f7134b83459fa0604305cba135875976ec066d417b59e8c6abc133c133c133c133c3fef3a2938ee43f1593d1ae52dbb26751fe64b7c133c136b0506b77519a519aaff4013f779663cacb50187b262e8a57053c7ac4d5003c9dee6c84c96b6609e69f5e476dc69a7736725acd6a5c96e508f10fa992bb4d5f78ddff1ac405488dd7f784f", "hex");
        const decodedSeal = Seal.decode(seal);
        const mapped = decodeSeal(decodedSeal, SupplementarySheet);

        expect(mapped.mrz).toBe("ATD<<RESIDORCE<<ROLAND<<<<<<<<<<<<<<6525845096USA7008038M2201018<<<<<<06");
        expect(mapped.number).toBe("PA0000005");
        expect(compareMessageLists(encodeSeal(mapped), decodedSeal.messageList)).toBeTrue();
    });
});