import { bytesToNumberBE } from "@noble/curves/utils.js";
import { C40Encoder, DateEncoder, DerTLV, intToBytesBE } from "../utils.js";
import { type Seal } from "./vds.js";

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

interface Feature {
    tag: number;
    name: string;
    coding: FeatureCoding;
    required: boolean;
}

interface DocumentMeta {
    documentRef: number;
    version: number;
}

interface ClassSchema {
    features: Feature[];
}

type Constructor<T extends object = object> = new (...args: any[]) => T;
type SealSchema = DocumentMeta & ClassSchema;

const vdsDocumentStorage = new Map<Function, DocumentMeta>();
const vdsSchemaStorage = new Map<Constructor, ClassSchema>();

const assertFeatureType = (feature: Feature, value: unknown) => {
    switch (feature.coding) {
        case FeatureCoding.C40_STRING:
        case FeatureCoding.UTF8_STRING:
        case FeatureCoding.MRZ:
        case FeatureCoding.MASKED_DATE:
            if (typeof value !== "string") throw new TypeError(`Feature "${feature.name}" (${feature.tag}) expects string, got ${typeof value}`);
            return;
        case FeatureCoding.BINARY:
            if (!(value instanceof Uint8Array)) throw new TypeError(`Feature "${feature.name}" (${feature.tag}) expects Uint8Array`);
            return;
        case FeatureCoding.INT:
            if (typeof value !== "bigint") throw new TypeError(`Feature "${feature.name}" (${feature.tag}) expects bigint, got ${typeof value}`);
            return;
        case FeatureCoding.DATE:
            if (!(value instanceof Date) || Number.isNaN(value.getTime())) throw new TypeError(`Feature "${feature.name}" (${feature.tag}) expects valid Date`);
            return;
        default:
            throw new Error(`Unsupported FeatureCoding: ${feature.coding}`);
    }
}
const assertDecodedType = (feature: Feature, value: unknown) => {
    try {
        assertFeatureType(feature, value);
    } catch (e) {
        throw new TypeError(`Decoded value for feature "${feature.name}" (${feature.tag}) has invalid type`);
    }
}

const getSealSchema = <T extends object>(ctor: Constructor<T>): SealSchema => {
    const document = vdsDocumentStorage.get(ctor);
    if (!document) throw new Error(`@VDSDocument is missing on ${ctor.name}`);

    const schema = vdsSchemaStorage.get(ctor);
    if (!schema) throw new Error(`No VDS schema for class ${ctor.name}`);
      
    return {
        documentRef: document.documentRef,
        version: document.version,
        features: schema.features
    }
}

export const VDSDocument =
    (options: DocumentMeta): ClassDecorator =>
    (target) => {
        if (vdsDocumentStorage.has(target)) throw new Error(`VDSDocument already defined for ${target.name}`);
        vdsDocumentStorage.set(target, { documentRef: options.documentRef, version: options.version, });
    }

interface VDSPropOptions {
    tag: number;
    coding: FeatureCoding;
    optional?: boolean;
}
type VDSPropDecorator = (target: object, propertyKey: string) => void;
export const VDSProp =
    (options: VDSPropOptions): VDSPropDecorator =>
    (target, propertyKey) => {
        const ctor = target.constructor as Constructor;
        let schema = vdsSchemaStorage.get(ctor);
        if (!schema) {
            schema = { features: [] };
            vdsSchemaStorage.set(ctor, schema);
        }
        if (schema.features.some(f => f.tag === options.tag)) throw new Error(`Duplicate tag ${options.tag} in ${ctor.name}`);

        schema.features.push({
            tag: options.tag,
            name: propertyKey,
            coding: options.coding,
            required: !options.optional,
        });
    }

export const decodeSeal = <T extends object>(seal: Seal, ctor: Constructor<T>): T => {
    const schema = getSealSchema(ctor);
    if (seal.header.version !== schema.version) throw new Error("Seal version mismatch");
    if (seal.header.documentRef !== schema.documentRef) throw new Error("Seal documentRef mismatch");

    const instance = new ctor();
    for (const feature of schema.features) {
        const message = seal.messageList.find(m => m.tag === feature.tag);
        if (!message) {
            if (feature.required) throw new Error(`Feature "${feature.name}" (${feature.tag}) is required but missing`);
            continue;
        }

        let value: unknown;
        switch (feature.coding) {
            case FeatureCoding.C40_STRING:
              value = C40Encoder.decode(message.value);
              break;
            case FeatureCoding.MRZ:
                value = C40Encoder.decode(message.value).replaceAll(" ", "<");
                break;
            case FeatureCoding.UTF8_STRING:
                value = new TextDecoder().decode(message.value);
                break;
            case FeatureCoding.BINARY:
                value = message.value;
                break;
            case FeatureCoding.DATE:
                value = DateEncoder.decode(message.value);
                break;
            case FeatureCoding.MASKED_DATE:
                value = DateEncoder.decodeMaskedDate(message.value);
                break;
            case FeatureCoding.INT:
                value = bytesToNumberBE(message.value);
                break;
            default:
                throw new Error(`Unsupported coding: ${feature.coding}`);
        }
        assertDecodedType(feature, value);
        (instance as any)[feature.name] = value;
    }
    return instance;
}

export const encodeSeal = <T extends object>(instance: T): DerTLV[] => {
    const ctor = instance.constructor as Constructor<T>;
    const schema = getSealSchema(ctor);
    const result: DerTLV[] = [];

    for (const feature of schema.features) {
        const value = (instance as any)[feature.name];
        if (value === undefined || value === null) {
            if (feature.required) throw new Error(`Feature "${feature.name}" (${feature.tag}) is required but missing`);
            continue;
        }
        assertFeatureType(feature, value);

        let encoded: Uint8Array;
        switch (feature.coding) {
            case FeatureCoding.C40_STRING:
            case FeatureCoding.MRZ:
                encoded = C40Encoder.encode(value as string);
                break;
            case FeatureCoding.UTF8_STRING:
                encoded = new TextEncoder().encode(value as string);
                break;
            case FeatureCoding.BINARY:
                encoded = value as Uint8Array;
                break;
            case FeatureCoding.DATE:
                encoded = DateEncoder.encode(value as Date);
                break;
            case FeatureCoding.MASKED_DATE:
                encoded = DateEncoder.encodeMaskedDate(value as string);
                break;
            case FeatureCoding.INT:
                encoded = intToBytesBE(value as bigint);
                break;
            default:
                throw new Error(`Unsupported coding: ${feature.coding}`);
        }

        result.push(new DerTLV(feature.tag, encoded));
    }

    return result;
}