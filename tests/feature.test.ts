import { describe, test, expect } from "bun:test";
import { FeatureCoding, mapSealToFeatures, Seal, type SealSchema } from "../src";

// Schemas from https://github.com/tsenger/vdstools/blob/main/src/commonMain/resources/SealCodings.json
const ARRIVAL_ATTESTATION = {
    documentRef: 0xfd02,
    version: 3,
    features: [
        {
            name: "MRZ",
            coding: FeatureCoding.MRZ,
            tag: 2,
            required: true
        },
        {
            name: "AZR",
            coding: FeatureCoding.C40_STRING,
            tag: 3,
            required: true
        }
    ]
} as const satisfies SealSchema;

const ADDRESS_STICKER_ID = {
    documentRef: 0xf908,
    version: 4,
    features: [
        {
            name: "DOCUMENT_NUMBER",
            coding: FeatureCoding.C40_STRING,
            tag: 1,
            required: true
        },
        {
            name: "AGS",
            coding: FeatureCoding.C40_STRING,
            tag: 2,
            required: true
        },
        {
            name: "ADDRESS",
            coding: FeatureCoding.C40_STRING,
            tag: 3,
            required: true
        }
    ]
} as const satisfies SealSchema;

const ADDRESS_STICKER_PASSPORT = {
    documentRef: 0xf80a,
    version: 4,
    features: [
        {
            name: "DOCUMENT_NUMBER",
            coding: FeatureCoding.C40_STRING,
            tag: 1,
            required: true
        },
        {
            name: "AGS",
            coding: FeatureCoding.C40_STRING,
            tag: 2,
            required: true
        },
        {
            name: "POSTAL_CODE",
            coding: FeatureCoding.C40_STRING,
            tag: 3,
            required: true
        }
    ]
} as const satisfies SealSchema;

const ICAO_EMERGENCY_TRAVEL_DOCUMENT = {
    documentRef: 0x5e03,
    version: 4,
    features: [
        {
            name: "MRZ",
            coding: FeatureCoding.MRZ,
            tag: 2,
            required: true
        }
    ]
} as const satisfies SealSchema;

const ICAO_VISA = {
    documentRef: 0x5d01,
    version: 4,
    features: [
        {
            name: "MRZ_MRVA",
            coding: FeatureCoding.MRZ,
            tag: 1
        },
        {
            name: "MRZ_MRVB",
            coding: FeatureCoding.MRZ,
            tag: 2
        },
        {
            name: "NUMBER_OF_ENTRIES",
            coding: FeatureCoding.INT,
            tag: 3,
            required: true
        },
        {
            name: "DURATION_OF_STAY",
            coding: FeatureCoding.BINARY,
            tag: 4,
            required: true
        },
        {
            name: "PASSPORT_NUMBER",
            coding: FeatureCoding.C40_STRING,
            tag: 5,
            required: true
        },
        {
            name: "VISA_TYPE",
            coding: FeatureCoding.BINARY,
            tag: 6,
            required: true
        },
        {
            name: "ADDITIONAL_FEATURES",
            coding: FeatureCoding.BINARY,
            tag: 7
        },
    ]
} as const satisfies SealSchema;

const RESIDENCE_PERMIT = {
    documentRef: 0xfb06,
    version: 4,
    features: [
        {
            name: "MRZ",
            coding: FeatureCoding.MRZ,
            tag: 2,
            required: true
        },
        {
            name: "PASSPORT_NUMBER",
            coding: FeatureCoding.C40_STRING,
            tag: 3,
            required: true
        }
    ]
} as const satisfies SealSchema;

const SOCIAL_INSURANCE_CARD = {
    documentRef: 0xfc04,
    version: 3,
    features: [
        {
            name: "SOCIAL_INSURANCE_NUMBER",
            coding: FeatureCoding.C40_STRING,
            tag: 1,
            required: true
        },
        {
            name: "SURNAME",
            coding: FeatureCoding.UTF8_STRING,
            tag: 2,
            required: true
        },
        {
            name: "FIRST_NAME",
            coding: FeatureCoding.UTF8_STRING,
            tag: 3,
            required: true
        },
        {
            name: "BIRTH_NAME",
            coding: FeatureCoding.UTF8_STRING,
            tag: 4
        }
    ]
} as const satisfies SealSchema;

const SUPPLEMENTARY_SHEET = {
    documentRef: 0xfa06,
    version: 4,
    features: [
        {
            name: "MRZ",
            coding: FeatureCoding.MRZ,
            tag: 4,
            required: true
        },
        {
            name: "SHEET_NUMBER",
            coding: FeatureCoding.C40_STRING,
            tag: 5,
            required: true
        }
    ]
} as const satisfies SealSchema;

describe("Feature", () => {
    test("#1 (ICAO_VISA)", () => {
        const seal = Buffer.from("dc03d9c5d9cac8a73a990f7134b834595d01022cdd52134a74da1347c6fed95cb89f9fce133c133c133c133c203833734aaf47f0c32f1a1e20eb2625393afe310403a00000050633be1fed20c603010c0601aa0701bbff400b276b4522526b723e2140f14bef1c25048cfed9223268c24337e7a6b5b9f02b1e15c86734ef7101d983869278ce1066694dd80e8b842b82b592db6fd56c10ae", "hex");
        const decodedSeal = Seal.decode(seal);
        const mapped = mapSealToFeatures(decodedSeal, ICAO_VISA)

        expect(mapped.MRZ_MRVB).toBe("VCD<<DENT<<ARTHUR<PHILIP<<<<<<<<<<<<1234567XY7GBR5203116M2005250");
        expect(mapped.NUMBER_OF_ENTRIES).toBe(12n);
        expect(mapped.DURATION_OF_STAY).toStrictEqual(new Uint8Array([0xA0,0,0]));
        expect(mapped.PASSPORT_NUMBER).toBe("47110815P");
        expect(mapped.VISA_TYPE).toStrictEqual(new Uint8Array([0xAA]));
        expect(mapped.ADDITIONAL_FEATURES).toStrictEqual(new Uint8Array([0xBB]));
    });

    test("#2 (ARRIVAL_ATTESTATION)", () => {
        const seal = Buffer.from("dc02d9c5d9cac8a51a780f7134b83459fd020230a56213535bd4caecc87ca4ccaeb4133c133c133c133c133c3fef3a2938ee43f1593d1ae52dbb26751fe64b7c133c136b030859e9203833736d24ff40a353a998b785470536187860093d55325a06e66fe917bfa1f6fb62c5016c66a481ec6f2c7c18da9682f0c2e0b592f6eeb11ca6c6994b37ca2950d6fadd63264d", "hex");
        const decodedSeal = Seal.decode(seal);
        const mapped = mapSealToFeatures(decodedSeal, ARRIVAL_ATTESTATION);

        expect(mapped.MRZ).toBe("MED<<MANNSENS<<MANNY<<<<<<<<<<<<<<<<6525845096USA7008038M2201018<<<<<<06");
        expect(mapped.AZR).toBe("ABC123456DEF");
    });

    test("#3 (ADDRESS_STICKER_ID)", () => {
        const seal = Buffer.from("dc03d9c5d9cac8a73a990f7134b83459f9080106cf3519af974c02061a70208519a1030e395e463e740c749fad19d31efe32ff40a31bf6877ef4b1a9c49b80aa52dddad07e70f55fd5f0cead9d46aaf2abde5a5661ae81ae9fea2b99a1066294d7b758074b286e0c99b198a6b48f299d07d55443", "hex");
        const decodedSeal = Seal.decode(seal);
        const mapped = mapSealToFeatures(decodedSeal, ADDRESS_STICKER_ID);

        expect(mapped.DOCUMENT_NUMBER).toBe("T2000AK47");
        expect(mapped.AGS).toBe("05314000");
        expect(mapped.ADDRESS).toBe("53175HEINEMANNSTR11");
    });

    test("#4 (ADDRESS_STICKER_PASSPORT)", () => {
        const seal = Buffer.from("dc03d9c5d9cac8a73a990f7134b83459f80a0106b77a38e596ce02061a203a4d1fe1030426532081ff409238e9e0323ba470be32f6d2ece1d12ee34ccc69f13efeb206d729369ae70b2a2965694e5c88c46e2bf9e8b6b28197c4e1f807af826295f1e571159e64b8bf2b", "hex");
        const decodedSeal = Seal.decode(seal);
        const mapped = mapSealToFeatures(decodedSeal, ADDRESS_STICKER_PASSPORT);

        expect(mapped.DOCUMENT_NUMBER).toBe("PA5500K11");
        expect(mapped.AGS).toBe("03359010");
        expect(mapped.POSTAL_CODE).toBe("21614");
    });

    test("#5 (RESIDENCE_PERMIT)", () => {
        const seal = Buffer.from("dc03d9c5d9cac8a73a990f7134b83459fb0602305cba135875976ec066d417b59e8c6abc133c133c133c133c3fef3a2938ee43f1593d1ae52dbb26751fe64b7c133c136b0306d79519a65306ff40a1f621437b25e0dc6177182297c47544890177ebd0e89b1d1ec9f994ed6fe60e5561fac9bc9e723ff8f60c679f6a23b938ee6584f852476f8c72a05e3f9eb87e", "hex");
        const decodedSeal = Seal.decode(seal);
        const mapped = mapSealToFeatures(decodedSeal, RESIDENCE_PERMIT);

        expect(mapped.MRZ).toBe("ATD<<RESIDORCE<<ROLAND<<<<<<<<<<<<<<6525845096USA7008038M2201018<<<<<<06");
        expect(mapped.PASSPORT_NUMBER).toBe("UFO001979");
    });

    test("#6 (SOCIAL_INSURANCE_CARD)", () => {
        const seal = Buffer.from("dc02d9c5d9cac8a51a780f7134b83459fc0401083fee456d2de019a8020b506572736368776569c39f03054f7363617204134ac3a2636f62c3a96e69646963747572697573ff40350f4b68832a812cb9afdd2eec0b1c6c8a5fabba3f48d4a550af0305a2d23807a9c16d0e49b65a61e294521a30b0b14a68d13b8b981667d200e9036da4e93f75", "hex");
        const decodedSeal = Seal.decode(seal);
        const mapped = mapSealToFeatures(decodedSeal, SOCIAL_INSURANCE_CARD);

        expect(mapped.SOCIAL_INSURANCE_NUMBER).toBe("65170839J003");
        expect(mapped.SURNAME).toBe("Perschweiß");
        expect(mapped.FIRST_NAME).toBe("Oscar");
        expect(mapped.BIRTH_NAME).toBe("Jâcobénidicturius");
    });

    test("#7 (ICAO_EMERGENCY_TRAVEL_DOCUMENT)", () => {
        const seal = Buffer.from("dc03d9c5d9cac8a73a990f7134b834595e0302308a0d62b9d917a4cca93ca4d0edfc133c133c133c133c133c3fef3a2938ee43f1593d1ae52dbb26751fe64b7c133c136bff403644690e5f2dd4e39b8bf10b4db669a38e60c8e6a46b3da0d7ad0f6aaf59af2326e924e4f96033ea096e89b8a5265aa9f2a39435f17120febf9334af51618d94", "hex");
        const decodedSeal = Seal.decode(seal);
        const mapped = mapSealToFeatures(decodedSeal, ICAO_EMERGENCY_TRAVEL_DOCUMENT);

        expect(mapped.MRZ).toBe("I<GBRSUPAMANN<<MARY<<<<<<<<<<<<<<<<<6525845096USA7008038M2201018<<<<<<06");
    });

    test("#8 (SUPPLEMENTARY_SHEET)", () => {
        const seal = Buffer.from("dc03d9c5d9cac8a73a990f7134b83459fa0604305cba135875976ec066d417b59e8c6abc133c133c133c133c3fef3a2938ee43f1593d1ae52dbb26751fe64b7c133c136b0506b77519a519aaff4013f779663cacb50187b262e8a57053c7ac4d5003c9dee6c84c96b6609e69f5e476dc69a7736725acd6a5c96e508f10fa992bb4d5f78ddff1ac405488dd7f784f", "hex");
        const decodedSeal = Seal.decode(seal);
        const mapped = mapSealToFeatures(decodedSeal, SUPPLEMENTARY_SHEET);

        expect(mapped.MRZ).toBe("ATD<<RESIDORCE<<ROLAND<<<<<<<<<<<<<<6525845096USA7008038M2201018<<<<<<06");
        expect(mapped.SHEET_NUMBER).toBe("PA0000005");
    });
});