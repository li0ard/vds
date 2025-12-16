import { describe, test, expect } from "bun:test";
import { ICAOBarcode, IDBPayload } from "../src";

describe("Parsing (IDB)", () => {
    test("#1", () => {
        const barcode = "RDB1DPDNACWQAUX7WVPABAUCAGAQBACNV3CDBCICBBMFRWKZ3JNNWW64LTOV3XS635P37HASLXOZTF5LCVFHUQ7NWEO4NWVOEUZNZZ5JSVFMYIOTKGTQRP5LDIOUU2XQYP4UCMKKD3BCXTL2G2REAJT3DFD5FEPDSP7ZKYE";
        const decodedBarcode = ICAOBarcode.decode(barcode);

        expect(decodedBarcode.barcodeFlag).toBe("D");
        expect(decodedBarcode.isSigned).toBeTrue();
        expect(decodedBarcode.isZipped).toBeTrue();

        expect(decodedBarcode.header.countryIdentifier).toBe("D<<");
        expect(decodedBarcode.header.signatureAlgorithm).toBe(1);
        expect(decodedBarcode.header.certificateReference).toStrictEqual(new Uint8Array([5,4,3,2,1]));
        expect(decodedBarcode.header.signatureCreationDate).toBe("2024-10-18");
        expect(decodedBarcode.header.encoded).toStrictEqual(Buffer.from("6abc010504030201009b5d88", "hex"));

        expect(decodedBarcode.messageList.some(i => i.tag == 4)).toBeTrue();
        expect(decodedBarcode.messageList.find(i => i.tag == 4)?.encoded).toStrictEqual(Buffer.from("0410b0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "hex"));
        expect(decodedBarcode.payload.messageListEncoded).toStrictEqual(Buffer.from("61120410b0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "hex"));

        expect(decodedBarcode.payload.signerCertificate).toBeNull();
        expect(decodedBarcode.payload.certificateEncoded).toBeNull();

        expect(decodedBarcode.payload.signature!.r).toBe(3868470656829979781525212049074451316257964222098919014007767999310n);
        expect(decodedBarcode.payload.signature!.s).toBe(1842692252577928447025948074334576723648333757006983594140827460551n);
        expect(decodedBarcode.payload.signature!.encoded).toStrictEqual(Buffer.from("7f3824bbbb332f562a94f487db623b8db55c4a65b9cf532a959843a6a34e117f56343a94d5e187f28262943d84579af46d44804cf6328fa523c7", "hex"));
        expect(decodedBarcode.payload.encoded).toStrictEqual(Buffer.from("6abc010504030201009b5d8861120410b0b1b2b3b4b5b6b7b8b9babbbcbdbebf7f3824bbbb332f562a94f487db623b8db55c4a65b9cf532a959843a6a34e117f56343a94d5e187f28262943d84579af46d44804cf6328fa523c7", "hex"));

        expect(decodedBarcode.signedBytes).toStrictEqual(Buffer.from("6abc010504030201009b5d8861120410b0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "hex"));
        expect(decodedBarcode.signatureBytes).toStrictEqual(Buffer.from("303c021c24bbbb332f562a94f487db623b8db55c4a65b9cf532a959843a6a34e021c117f56343a94d5e187f28262943d84579af46d44804cf6328fa523c7", "hex"));
        expect(decodedBarcode.encoded).toStrictEqual(barcode);
    });

    test("#2", () => {
        const barcode = "RDB1ANK6GCEQECCYLDMVTWS23NN5YXG5LXPF5X27Q";
        const decodedBarcode = ICAOBarcode.decode(barcode);

        expect(decodedBarcode.barcodeFlag).toBe("A");
        expect(decodedBarcode.isSigned).toBeFalse();
        expect(decodedBarcode.isZipped).toBeFalse();

        expect(decodedBarcode.header.countryIdentifier).toBe("D<<");
        expect(decodedBarcode.header.encoded).toStrictEqual(Buffer.from("6abc", "hex"));

        expect(decodedBarcode.messageList.some(i => i.tag == 4)).toBeTrue();
        expect(decodedBarcode.messageList.find(i => i.tag == 4)?.encoded).toStrictEqual(Buffer.from("0410b0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "hex"));
        expect(decodedBarcode.payload.messageListEncoded).toStrictEqual(Buffer.from("61120410b0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "hex"));

        expect(decodedBarcode.payload.signerCertificate).toBeNull();
        expect(decodedBarcode.payload.certificateEncoded).toBeNull();

        expect(decodedBarcode.payload.signature).toBeNull();

        expect(decodedBarcode.signedBytes).toStrictEqual(Buffer.from("6abc61120410b0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "hex"));
        expect(decodedBarcode.signatureBytes).toBeNull();
        expect(decodedBarcode.encoded).toStrictEqual(barcode);
    });
});

describe("Generation (IDB)", () => {
    test("#1 (Signed + compressed)", () => {
        const payload = IDBPayload.decode(
            Buffer.from("6abc010504030201009b5d8861120410b0b1b2b3b4b5b6b7b8b9babbbcbdbebf7f3824bbbb332f562a94f487db623b8db55c4a65b9cf532a959843a6a34e117f56343a94d5e187f28262943d84579af46d44804cf6328fa523c7", "hex"),
            true
        );

        expect(new ICAOBarcode(true, true, payload).encoded).toStrictEqual("RDB1DPDNACWQAUX7WVPABAUCAGAQBACNV3CDBCICBBMFRWKZ3JNNWW64LTOV3XS635P37HASLXOZTF5LCVFHUQ7NWEO4NWVOEUZNZZ5JSVFMYIOTKGTQRP5LDIOUU2XQYP4UCMKKD3BCXTL2G2REAJT3DFD5FEPDSP7ZKYE");
    });

    test("#2 (Signed + not compressed)", () => {
        const payload = IDBPayload.decode(
            Buffer.from("6abc010504030201009b5d8861120410b0b1b2b3b4b5b6b7b8b9babbbcbdbebf7f3824bbbb332f562a94f487db623b8db55c4a65b9cf532a959843a6a34e117f56343a94d5e187f28262943d84579af46d44804cf6328fa523c7", "hex"),
            true
        );

        expect(new ICAOBarcode(true, false, payload).encoded).toStrictEqual("RDB1BNK6ACBIEAMBACAE3LWEGCEQECCYLDMVTWS23NN5YXG5LXPF5X27X6OBEXO5TGL2WFKKPJB63MI5Y3NK4JJS3TT2TFKKZQQ5GUNHBC72WGQ5JJVPBQ7ZIEYUUHWCFPGXUNVCIATHWGKH2KI6H");
    });

    test("#3 (Not signed + compressed)", () => {
        const payload = IDBPayload.decode(
            Buffer.from("6abc61120510b0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "hex"),
            false
        );

        expect(new ICAOBarcode(false, true, payload).encoded).toStrictEqual("RDB1CPDNACFQA5H7WVPDBCICRBMFRWKZ3JNNWW64LTOV3XS635P4DDIGSO");
    });

    test("#4 (Not signed + not compressed)", () => {
        const payload = IDBPayload.decode(
            Buffer.from("6abc61120510b0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "hex"),
            false
        );

        expect(new ICAOBarcode(false, false, payload).encoded).toStrictEqual("RDB1ANK6GCEQFCCYLDMVTWS23NN5YXG5LXPF5X27Q");
    });
});