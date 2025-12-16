import { bytesToNumberBE } from "@noble/curves/utils.js";
import { C40Encoder, DateEncoder } from "../utils.js";
import type { Seal } from "./vds.js";

/** Feature encoding */
export enum FeatureCoding {
    /** String encoded with C40 */
    C40_STRING = 0,
    /** Raw bytes */
    BINARY = 1,
    /** Integer */
    INT = 2,
    /** Date */
    DATE = 3,
    /** Masked date */
    MASKED_DATE = 4,

    // Special cases
    /** Machine readable zone (MRZ) */
    MRZ = 10,
    /** String encoded with UTF-8 */
    UTF8_STRING = 11
}

type CodingTypeMap = {
    [FeatureCoding.C40_STRING]: string;
    [FeatureCoding.BINARY]: Uint8Array;
    [FeatureCoding.INT]: bigint;
    [FeatureCoding.DATE]: Date;
    [FeatureCoding.MASKED_DATE]: string;
    [FeatureCoding.MRZ]: string;
    [FeatureCoding.UTF8_STRING]: string;
}

export interface Feature {
    tag: number;
    name: string;
    coding: FeatureCoding;
    required?: boolean;
}

export interface SealSchema {
    documentRef: number;
    version: number;
    features: Feature[];
}

export type SchemaResult<T extends SealSchema> = {
    [F in T["features"][number] as F["name"]]: F["required"] extends true
        ? CodingTypeMap[F["coding"]]
        : CodingTypeMap[F["coding"]] | undefined;
}

export const mapSealToFeatures = <T extends SealSchema>(seal: Seal, schema: T): SchemaResult<T> => {
    if(seal.header.version != schema.version) throw new Error("Seal version mismatch");
    if(seal.header.documentRef != schema.documentRef) throw new Error("Seal documentRef mismatch");

    const result = new Map<string, any>();
    for(const feature of schema.features) {
        const message = seal.messageList.find(i => i.tag == feature.tag);
        if(!message && feature.required) throw new Error(`Feature "${feature.name}" (${feature.tag}) required in schema, but missing in seal`);
        if(message) {
            switch (feature.coding) {
                case FeatureCoding.C40_STRING:
                    result.set(feature.name, C40Encoder.decode(message.value));
                    break;
                case FeatureCoding.BINARY:
                    result.set(feature.name, message.value);
                    break;
                case FeatureCoding.DATE:
                    result.set(feature.name, DateEncoder.decode(message.value));
                    break;
                case FeatureCoding.MASKED_DATE:
                    result.set(feature.name, DateEncoder.decodeMaskedDate(message.value));
                    break;
                case FeatureCoding.INT:
                    result.set(feature.name, bytesToNumberBE(message.value));
                    break;
                case FeatureCoding.MRZ:
                    result.set(feature.name, C40Encoder.decode(message.value).replaceAll(" ", "<"));
                    break;
                case FeatureCoding.UTF8_STRING:
                    result.set(feature.name, new TextDecoder().decode(message.value));
                    break;
            }
        }
    }

    return Object.fromEntries(result) as SchemaResult<T>;
}