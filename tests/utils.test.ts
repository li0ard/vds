import { describe, test, expect } from "bun:test";
import { C40Encoder, DateEncoder } from "../src";

describe("Date encoding", () => {
    const date1 = new Date(1957, 2, 25, 8, 15, 22);
    const date2 = "19xx-xx-01";

    test("Date", () => {
        const encoded = new Uint8Array([0x31,0x9E,0xF5]);
        expect(DateEncoder.encode(date1)).toStrictEqual(encoded);
        // Date without time
        expect(DateEncoder.decode(encoded).toISOString()).toStrictEqual(new Date(date1.getFullYear(), date1.getMonth(), date1.getDate()).toISOString());
    });

    test("DateTime", () => {
        const encoded = new Uint8Array([0x02,0xF5,0x27,0xBF,0x25,0xB2]);
        expect(DateEncoder.encodeDateTime(date1)).toStrictEqual(encoded);
        expect(DateEncoder.decodeDateTime(encoded).toISOString()).toStrictEqual(date1.toISOString());
    });

    test("Masked date", () => {
        const encoded = new Uint8Array([0xC3,0x00,0x2E,0x7C]);
        expect(DateEncoder.encodeMaskedDate(date2)).toStrictEqual(encoded);
        expect(DateEncoder.decodeMaskedDate(encoded)).toStrictEqual(date2);
    });
});

describe("C40 encoding", () => {
    const string = "XK CD";

    test("#1", () => {
        const encoded = new Uint8Array([0xEB,0x04,0x66,0xA9]);
        expect(C40Encoder.encode(string)).toStrictEqual(encoded);
    });

    test("#2", () => {
        const encoded = new Uint8Array([0xEB,0x11,0xFE,0x45]);
        expect(C40Encoder.encode(string.replace(" ", ""))).toStrictEqual(encoded);
    });
});