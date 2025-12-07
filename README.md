<p align="center">
    <a href="https://github.com/li0ard/vds/">
        <img src="https://raw.githubusercontent.com/li0ard/vds/main/.github/logo.svg" alt="vds logo" title="vds" width="120" /><br>
    </a><br>
    <b>@li0ard/vds</b><br>
    <b>simple library for visible digital seals (VDS)</b>
    <br>
    <a href="https://li0ard.is-cool.dev/vds">docs</a>
    <br><br>
    <a href="https://github.com/li0ard/vds/actions/workflows/test.yml"><img src="https://github.com/li0ard/vds/actions/workflows/test.yml/badge.svg" /></a>
    <a href="https://github.com/li0ard/vds/blob/main/LICENSE"><img src="https://img.shields.io/github/license/li0ard/vds" /></a>
    <br>
    <a href="https://npmjs.com/package/@li0ard/vds"><img src="https://img.shields.io/npm/v/@li0ard/vds" /></a>
    <a href="https://jsr.io/@li0ard/vds"><img src="https://jsr.io/badges/@li0ard/vds" /></a>
    <br>
    <hr>
</p>

## Features

- Simple: Hides decoding process and provides simple and modern API
- Type-Safe: Most of the APIs are strictly typed to help your workflow
- Compliance: Fully complies with ICAO 9303, BSI TR-03137 standards
- Supports Bun, Node.js, Deno, Browsers, Cloudflare Workers
- Supports many curves from [`@noble/curves`](https://github.com/paulmillr/noble-curves/)

## Installation

```bash
# from NPM
npm i @li0ard/vds

# from JSR
bunx jsr add @li0ard/vds 
```

## Usage

### Parse digital seal
```ts
import { Seal } from "@li0ard/vds";

const seal = Buffer.from("DC03....", "hex");
const decodedSeal = Seal.decode(seal);

console.log(seal);
```

### Verify digital seal
```ts
import { Seal, SealVerifier } from "@li0ard/vds";
import { brainpoolP256r1 } from "@noble/curves/misc.js";

const publicKey = Buffer.from("0408....", "hex");
const verifier = new SealVerifier(brainpoolP256r1, publicKey);

const seal = Buffer.from("DC03....", "hex");
const decodedSeal = Seal.decode(seal);

console.log(verifier.verify(decodedSeal));
```

## Links

- [vdstools](https://github.com/tsenger/vdstools) - An Open Source Kotlin Implementation of VDS (greatly inspired)
- [ICAO 9303](https://icao.int/publications/doc-series/doc-9303) - Specifications to VDS
- [BSI TR-03137](https://bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03137/tr03137_node.html) - Specifications to VDS (with example documents)